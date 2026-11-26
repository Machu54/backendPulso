require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { ObjectId } = require('mongodb');
const { connectDB, getDB } = require('./conection');

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ==========================================
// HELPERS GENERALES Y CIFRADO COMPATIBLE LARAVEL
// ==========================================

async function cifrarPasswordLaravel(passwordPlana) {
  const hash = await bcrypt.hash(String(passwordPlana), 10);
  // Mantiene el prefijo $2y$ de Laravel para que tanto PHP como Node lo lean igual
  return hash.replace(/^\$2[ab]\$/, '$2y$');
}

async function verificarPassword(passwordPlana, hashGuardado) {
  if (!passwordPlana || !hashGuardado) return false;
  const passStr = String(passwordPlana);
  const hashStr = String(hashGuardado).trim();

  // Si es un hash bcrypt ($2y$, $2a$, $2b$)
  if (/^\$2[aby]\$/.test(hashStr)) {
    const hashCompatible = hashStr.replace(/^\$2y\$/, '$2a$');
    return await bcrypt.compare(passStr, hashCompatible);
  }

  // Fallback por si algún usuario de prueba en MongoDB se guardó en texto plano
  return passStr === hashStr;
}

function resolverEmail(req, defaultEmail = 'admin@pulso.com') {
  if (req.headers['x-user-email']) {
    return String(req.headers['x-user-email']).trim().toLowerCase();
  }
  if (req.body && req.body.user_email) {
    return String(req.body.user_email).trim().toLowerCase();
  }
  if (req.query && req.query.user_email) {
    return String(req.query.user_email).trim().toLowerCase();
  }
  return defaultEmail;
}

function filtroIdMongo(id) {
  const idStr = String(id);
  if (ObjectId.isValid(idStr) && idStr.length === 24) {
    return { $or: [{ _id: new ObjectId(idStr) }, { _id: idStr }, { id: idStr }] };
  }
  return { $or: [{ _id: idStr }, { id: idStr }] };
}

function cifrarCesar(texto, desplazamiento = 5) {
  if (!texto) return texto;
  let resultado = '';
  for (let i = 0; i < texto.length; i++) {
    const ascii = texto.charCodeAt(i);
    if (ascii >= 65 && ascii <= 90) {
      resultado += String.fromCharCode((((ascii - 65 + desplazamiento) % 26) + 26) % 26 + 65);
    } else if (ascii >= 97 && ascii <= 122) {
      resultado += String.fromCharCode((((ascii - 97 + desplazamiento) % 26) + 26) % 26 + 97);
    } else if (ascii >= 48 && ascii <= 57) {
      resultado += String.fromCharCode((((ascii - 48 + desplazamiento) % 10) + 10) % 10 + 48);
    } else {
      resultado += texto[i];
    }
  }
  return resultado;
}

function descifrarCesar(texto, desplazamiento = 5) {
  if (!texto) return texto;
  return cifrarCesar(texto, -desplazamiento);
}

function formatearHoras(horas) {
  return horas.map((hora) => {
    const h = String(hora).trim();
    if (h.includes(':')) {
      const [hh, mm] = h.split(':');
      return `${String(parseInt(hh, 10) || 0).padStart(2, '0')}:${String(parseInt(mm, 10) || 0).padStart(2, '0')}`;
    }
    if (/^\d+$/.test(h)) {
      return `${String(parseInt(h, 10)).padStart(2, '0')}:00`;
    }
    return h;
  });
}

function ahoraDateTime() {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

function validarDatosPaciente(body) {
  const requeridos = [
    { key: 'nombre', label: 'Nombre completo' },
    { key: 'sexo', label: 'Sexo' },
    { key: 'edad', label: 'Edad' },
    { key: 'domicilio', label: 'Domicilio completo' },
    { key: 'tipo_sangre', label: 'Tipo de sangre' },
    { key: 'alergias', label: 'Alergias conocidas' },
    { key: 'padecimientos', label: 'Padecimientos crónicos' },
    { key: 'contacto_emergencia_nombre', label: 'Nombre del contacto de emergencia' },
    { key: 'contacto_emergencia_parentesco', label: 'Parentesco del contacto' },
    { key: 'contacto_emergencia_telefono', label: 'Teléfono de emergencia' }
  ];

  const faltantes = requeridos.filter(
    (c) => body[c.key] === undefined || body[c.key] === null || String(body[c.key]).trim() === ''
  );

  if (faltantes.length > 0) {
    return `Faltan campos obligatorios del paciente: ${faltantes.map((f) => f.label).join(', ')}.`;
  }
  return null;
}

// ==========================================
// 1. AUTENTICACIÓN
// ==========================================

app.post('/api/iniciar-sesion', async (req, res) => {
  try {
    const { email, correo, password, contrasena } = req.body || {};
    const emailInput = email || correo;
    const passwordInput = password || contrasena;

    if (!emailInput || !passwordInput) {
      return res.status(422).json({
        message: 'La contraseña o correo ingresado es incorrecto.',
        errors: { email: ['La contraseña o correo ingresado es incorrecto.'] }
      });
    }

    const emailLimpio = String(emailInput).trim().toLowerCase();
    const db = getDB();
    const usuario = await db.collection('usuarios').findOne({
      $or: [
        { email: emailLimpio },
        { correo: emailLimpio },
        { id: emailLimpio },
        { _id: emailLimpio }
      ]
    });

    const hashGuardado = usuario ? (usuario.password || usuario.contrasena || '') : '';
    const passwordValido = await verificarPassword(passwordInput, hashGuardado);

    if (!usuario || !passwordValido) {
      return res.status(422).json({
        message: 'La contraseña o correo ingresado es incorrecto.',
        errors: { email: ['La contraseña o correo ingresado es incorrecto.'] }
      });
    }

    const nombre = usuario.nombre || usuario.name || 'Usuario Pulso';
    const tokenAcceso = crypto.randomBytes(30).toString('hex');

    return res.json({
      mensaje: 'Inicio de sesión exitoso',
      token_acceso: tokenAcceso,
      tipo_token: 'Bearer',
      usuario: {
        id: String(usuario.id || usuario._id || emailLimpio),
        nombre,
        name: nombre,
        correo: emailLimpio,
        email: emailLimpio,
        avatar:
          usuario.foto ||
          usuario.avatar ||
          `https://ui-avatars.com/api/?name=${encodeURIComponent(nombre)}&background=0D8ABC&color=fff`,
        rol: usuario.rol || 'administrador'
      }
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error interno al iniciar sesión', error: error.message });
  }
});

app.get('/api/usuario', async (req, res) => {
  try {
    const email = resolverEmail(req, '');
    if (!email) return res.json(null);
    const db = getDB();
    const usuario = await db.collection('usuarios').findOne(
      { $or: [{ email }, { correo: email }] },
      { projection: { password: 0, contrasena: 0 } }
    );
    return res.json(usuario || null);
  } catch (_) {
    return res.json(null);
  }
});

app.post('/api/cerrar-sesion', (req, res) => {
  return res.json({ mensaje: 'Sesión cerrada correctamente' });
});

// ==========================================
// 2. PERFIL DE USUARIO, REGISTRO Y CRUD USUARIOS
// ==========================================

app.put('/api/perfil', async (req, res) => {
  try {
    const email = resolverEmail(req);
    const { nombre, telefono, password } = req.body || {};

    const datosPerfil = {
      nombre,
      name: nombre,
      telefono: telefono || ''
    };

    if (password) {
      datosPerfil.password = await cifrarPasswordLaravel(password);
    }

    const db = getDB();
    await db.collection('usuarios').updateOne(
      { $or: [{ email }, { correo: email }] },
      { $set: datosPerfil }
    );
    const userActualizado = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });

    const { password: _, ...sinPass } = datosPerfil;

    return res.json({
      mensaje: 'Perfil actualizado exitosamente',
      usuario: {
        id: email,
        correo: email,
        email,
        telefono,
        avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(nombre || 'Usuario')}&background=0D8ABC&color=fff`,
        rol: userActualizado?.rol || 'administrador',
        ...sinPass
      }
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al actualizar perfil', error: error.message });
  }
});

app.get('/api/usuarios', async (req, res) => {
  const db = getDB();

  try {
    const listaMongo = await db.collection('usuarios').find({}, { projection: { password: 0, contrasena: 0 } }).toArray();
    if (listaMongo.length > 0) {
      return res.json(listaMongo);
    }
  } catch (_) {}

  const passwordDefault = await cifrarPasswordLaravel('admin123456');
  const usuariosBase = [
    {
      id: 'jdaniel.vb08@gmail.com',
      _id: 'jdaniel.vb08@gmail.com',
      nombre: 'Danielo',
      name: 'Danielo',
      email: 'jdaniel.vb08@gmail.com',
      password: passwordDefault,
      rol: 'paciente',
      telefono: '3322014606',
      estado: 'activo'
    },
    {
      id: 'admin@pulso.com',
      _id: 'admin@pulso.com',
      nombre: 'Juanito Admin',
      name: 'Juanito Admin',
      email: 'admin@pulso.com',
      password: passwordDefault,
      rol: 'administrador',
      telefono: '3312345678',
      estado: 'activo'
    },
    {
      id: 'alejandromixer17@gmail.com',
      _id: 'alejandromixer17@gmail.com',
      nombre: 'Alejandro Mixteco',
      name: 'Alejandro Mixteco',
      email: 'alejandromixer17@gmail.com',
      password: passwordDefault,
      rol: 'paciente',
      telefono: '3349815977',
      estado: 'activo'
    }
  ];

  try {
    await db.collection('usuarios').insertMany(usuariosBase.map((u) => ({ ...u })));
  } catch (_) {}

  return res.json(usuariosBase.map(({ password, ...rest }) => rest));
});

// REGISTRO DE CUIDADORES / DOCTORES / FAMILIARES
app.post('/api/usuarios', async (req, res) => {
  try {
    const {
      nombre,
      email,
      rol,
      telefono,
      password,
      acepto_privacidad,
      fecha_aceptacion_legal
    } = req.body || {};

    const rolesValidos = ['administrador', 'paciente', 'cuidador', 'doctor', 'familiar'];

    if (!nombre || String(nombre).trim().length < 3) {
      return res.status(422).json({ mensaje: 'El nombre completo es obligatorio (mínimo 3 caracteres).' });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())) {
      return res.status(422).json({ mensaje: 'Ingresa un correo electrónico válido.' });
    }
    if (!rol || !rolesValidos.includes(String(rol).toLowerCase())) {
      return res.status(422).json({ mensaje: 'Selecciona un rol válido (cuidador, familiar o doctor).' });
    }
    if (!password || String(password).length < 8) {
      return res.status(422).json({ mensaje: 'La contraseña debe tener al menos 8 caracteres.' });
    }

    const emailLower = String(email).trim().toLowerCase();
    const db = getDB();

    const yaExiste = await db.collection('usuarios').findOne({
      $or: [{ email: emailLower }, { correo: emailLower }]
    });
    if (yaExiste) {
      return res.status(422).json({ mensaje: 'Ya existe una cuenta registrada con ese correo electrónico.' });
    }

    const hash = await cifrarPasswordLaravel(password);

    const nuevo = {
      id: emailLower,
      _id: emailLower,
      nombre: String(nombre).trim(),
      name: String(nombre).trim(),
      email: emailLower,
      correo: emailLower,
      password: hash,
      rol: String(rol).toLowerCase(),
      telefono: telefono ? String(telefono).trim() : '',
      acepto_privacidad: Boolean(acepto_privacidad),
      fecha_aceptacion_legal: fecha_aceptacion_legal || new Date().toISOString(),
      estado: 'activo',
      foto: `https://ui-avatars.com/api/?name=${encodeURIComponent(nombre)}&background=0D8ABC&color=fff`,
      created_at: new Date().toISOString()
    };

    await db.collection('usuarios').insertOne({ ...nuevo });

    const { password: _, ...usuarioSinPass } = nuevo;
    return res.status(201).json({
      mensaje: 'Usuario registrado exitosamente',
      usuario: usuarioSinPass
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al registrar usuario', error: error.message });
  }
});

app.put('/api/usuarios/:id', async (req, res) => {
  try {
    const idLower = String(req.params.id).trim().toLowerCase();
    const { nombre, rol, telefono, estado, password } = req.body || {};

    const datosActualizar = {};
    if (nombre !== undefined) {
      datosActualizar.nombre = nombre;
      datosActualizar.name = nombre;
    }
    if (rol !== undefined) datosActualizar.rol = String(rol).toLowerCase();
    if (telefono !== undefined) datosActualizar.telefono = telefono;
    if (estado !== undefined) datosActualizar.estado = estado;
    if (password) datosActualizar.password = await cifrarPasswordLaravel(password);

    const db = getDB();
    await db.collection('usuarios').updateMany(
      { $or: [{ email: idLower }, { correo: idLower }, { _id: idLower }] },
      { $set: datosActualizar }
    );

    return res.json({ mensaje: 'Usuario actualizado exitosamente' });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al actualizar usuario', error: error.message });
  }
});

app.delete('/api/usuarios/:id', async (req, res) => {
  try {
    const idLower = String(req.params.id).trim().toLowerCase();
    const db = getDB();
    await db.collection('usuarios').deleteMany({
      $or: [{ email: idLower }, { correo: idLower }, { _id: idLower }]
    });

    return res.json({ mensaje: 'Usuario eliminado exitosamente' });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al eliminar usuario', error: error.message });
  }
});

// ==========================================
// 2.5 PERFILES DE PACIENTES (CREAR, LISTAR, EDITAR)
// ==========================================

app.post('/api/pacientes', async (req, res) => {
  try {
    const cuidadorEmail = resolverEmail(req);
    const body = req.body || {};

    const errorValidacion = validarDatosPaciente(body);
    if (errorValidacion) {
      return res.status(422).json({ mensaje: errorValidacion });
    }

    const nuevoPaciente = {
      id: crypto.randomBytes(8).toString('hex'),
      cuidador_email: cuidadorEmail,
      nombre: String(body.nombre).trim(),
      edad: Number(body.edad),
      fecha_nacimiento: body.fecha_nacimiento || '',
      sexo: String(body.sexo).trim(),
      telefono: body.telefono ? String(body.telefono).trim() : '',
      domicilio: String(body.domicilio).trim(),
      tipo_sangre: String(body.tipo_sangre).trim(),
      peso: body.peso ? String(body.peso).trim() : '',
      estatura: body.estatura ? String(body.estatura).trim() : '',
      alergias: String(body.alergias).trim(),
      padecimientos: String(body.padecimientos).trim(),
      medico_cabecera: body.medico_cabecera ? String(body.medico_cabecera).trim() : '',
      seguro_medico: body.seguro_medico ? String(body.seguro_medico).trim() : '',
      contacto_emergencia_nombre: String(body.contacto_emergencia_nombre).trim(),
      contacto_emergencia_parentesco: String(body.contacto_emergencia_parentesco).trim(),
      contacto_emergencia_telefono: String(body.contacto_emergencia_telefono).trim(),
      notas: body.notas ? String(body.notas).trim() : '',
      foto: `https://ui-avatars.com/api/?name=${encodeURIComponent(body.nombre)}&background=0D8ABC&color=fff`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const db = getDB();
    await db.collection('pacientes').insertOne({ ...nuevoPaciente });

    return res.status(201).json({
      mensaje: 'Perfil de paciente creado exitosamente',
      paciente: nuevoPaciente
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al crear perfil de paciente', error: error.message });
  }
});

app.get('/api/pacientes', async (req, res) => {
  try {
    const cuidadorEmail = resolverEmail(req);
    const db = getDB();
    const pacientes = await db.collection('pacientes').find({ cuidador_email: cuidadorEmail }).toArray();
    return res.json(pacientes);
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al obtener pacientes', error: error.message });
  }
});

app.put('/api/pacientes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const cuidadorEmail = resolverEmail(req);
    const body = req.body || {};

    const errorValidacion = validarDatosPaciente(body);
    if (errorValidacion) {
      return res.status(422).json({ mensaje: errorValidacion });
    }

    const updates = {
      nombre: String(body.nombre).trim(),
      edad: Number(body.edad),
      fecha_nacimiento: body.fecha_nacimiento || '',
      sexo: String(body.sexo).trim(),
      telefono: body.telefono ? String(body.telefono).trim() : '',
      domicilio: String(body.domicilio).trim(),
      tipo_sangre: String(body.tipo_sangre).trim(),
      peso: body.peso ? String(body.peso).trim() : '',
      estatura: body.estatura ? String(body.estatura).trim() : '',
      alergias: String(body.alergias).trim(),
      padecimientos: String(body.padecimientos).trim(),
      medico_cabecera: body.medico_cabecera ? String(body.medico_cabecera).trim() : '',
      seguro_medico: body.seguro_medico ? String(body.seguro_medico).trim() : '',
      contacto_emergencia_nombre: String(body.contacto_emergencia_nombre).trim(),
      contacto_emergencia_parentesco: String(body.contacto_emergencia_parentesco).trim(),
      contacto_emergencia_telefono: String(body.contacto_emergencia_telefono).trim(),
      notas: body.notas ? String(body.notas).trim() : '',
      foto: `https://ui-avatars.com/api/?name=${encodeURIComponent(body.nombre)}&background=0D8ABC&color=fff`,
      updated_at: new Date().toISOString()
    };

    const db = getDB();
    const filtro = {
      ...filtroIdMongo(id),
      cuidador_email: cuidadorEmail
    };

    await db.collection('pacientes').updateOne(filtro, { $set: updates });
    const pacienteActualizado = await db.collection('pacientes').findOne(filtro);

    return res.json({
      mensaje: 'Perfil del paciente actualizado correctamente',
      paciente: pacienteActualizado
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al actualizar paciente', error: error.message });
  }
});

// ==========================================
// 3. RESPALDOS LÓGICOS JSON
// ==========================================

app.get('/api/respaldo/exportar', async (req, res) => {
  const email = resolverEmail(req);
  const db = getDB();

  let userDb = {};
  try {
    userDb = (await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] })) || {};
  } catch (_) {}

  const nombre = userDb.nombre || userDb.name || 'Usuario Pulso';
  const correo = userDb.email || userDb.correo || email;

  let mediciones = [];
  let eventos = [];
  let medicamentos = [];
  try {
    [mediciones, eventos, medicamentos] = await Promise.all([
      db.collection('mediciones').find({}).toArray(),
      db.collection('eventos').find({}).toArray(),
      db.collection('medicamentos').find({}).toArray()
    ]);
  } catch (_) {}

  const datosRespaldo = {
    version: '1.0',
    fecha_exportacion: new Date().toISOString(),
    usuario: { nombre, correo },
    datos: {
      expediente: userDb.historial_medico || [],
      contactos: userDb.contactos_emergencia || [],
      mediciones,
      eventos,
      medicamentos
    }
  };

  const timestamp = new Date().toISOString().replace(/T/, '_').replace(/:/g, '-').slice(0, 19);
  const nombreArchivo = `respaldo_pulso_${timestamp}.json`;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${nombreArchivo}"`);
  return res.send(JSON.stringify(datosRespaldo, null, 2));
});

app.post('/api/respaldo/importar', async (req, res) => {
  const email = resolverEmail(req);

  try {
    const datos = req.body?.datos || req.body;

    if (!datos || !datos.version) {
      return res.status(422).json({ mensaje: 'El formato del respaldo JSON no es válido.' });
    }

    const db = getDB();
    const updates = {};
    if (datos.datos?.expediente !== undefined) updates.historial_medico = datos.datos.expediente;
    if (datos.datos?.contactos !== undefined) updates.contactos_emergencia = datos.datos.contactos;

    if (Object.keys(updates).length > 0) {
      await db.collection('usuarios').updateOne({ $or: [{ email }, { correo: email }] }, { $set: updates });
    }

    return res.json({ mensaje: 'Respaldo importado y restaurado exitosamente' });
  } catch (_) {
    return res.status(500).json({ mensaje: 'Error al importar el respaldo JSON' });
  }
});

// ==========================================
// 4. HISTORIAL MÉDICO (CIFRADO CÉSAR +5)
// ==========================================

app.get('/api/historial-medico', async (req, res) => {
  const email = resolverEmail(req);
  let historialCifrado = [];

  try {
    const db = getDB();
    let userDb = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });
    if (!userDb || !userDb.historial_medico) {
      userDb = await db.collection('usuarios').findOne({});
    }
    historialCifrado = userDb?.historial_medico || [];
  } catch (_) {
    historialCifrado = [];
  }

  if (typeof historialCifrado === 'string') {
    try {
      historialCifrado = JSON.parse(historialCifrado);
    } catch (_) {
      historialCifrado = [];
    }
  }

  const historialDescifrado = Array.isArray(historialCifrado)
    ? historialCifrado.map((registro) => {
        const reg = { ...registro };
        if (reg.diagnostico) reg.diagnostico = descifrarCesar(reg.diagnostico);
        if (reg.notas) reg.notas = descifrarCesar(reg.notas);
        return reg;
      })
    : [];

  return res.json({ historial: historialDescifrado });
});

app.post('/api/historial-medico', async (req, res) => {
  const { titulo, diagnostico, notas } = req.body || {};
  if (!titulo || !diagnostico) {
    return res.status(422).json({ mensaje: 'titulo y diagnostico son obligatorios.' });
  }

  const email = resolverEmail(req);
  const nuevoRegistro = {
    id: crypto.randomBytes(8).toString('hex'),
    fecha: new Date().toISOString(),
    titulo: String(titulo),
    diagnostico: cifrarCesar(String(diagnostico)),
    notas: cifrarCesar(notas ? String(notas) : '')
  };

  try {
    const db = getDB();
    const userDb = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });

    if (!userDb) {
      await db.collection('usuarios').insertOne({
        email,
        nombre: 'Usuario Admin',
        historial_medico: [nuevoRegistro]
      });
    } else {
      let historialActual = userDb.historial_medico || [];
      if (typeof historialActual === 'string') {
        historialActual = JSON.parse(historialActual) || [];
      }
      historialActual.push(nuevoRegistro);

      await db.collection('usuarios').updateOne(
        { $or: [{ email }, { correo: email }] },
        { $set: { historial_medico: historialActual } }
      );
    }
  } catch (_) {}

  return res.json({
    mensaje: 'Registro médico cifrado y guardado en MongoDB Atlas',
    registro: nuevoRegistro
  });
});

// ==========================================
// 5. MEDICIONES DE SALUD
// ==========================================

app.get('/api/mediciones', async (req, res) => {
  try {
    const db = getDB();

    try {
      await db.collection('mediciones').deleteMany({
        $or: [
          { tipo_medicion: { $regex: /paciente|random|test/i } },
          { valor: { $regex: /paciente/i } }
        ]
      });
    } catch (_) {}

    const email = req.headers['x-user-email'] || req.query.user_email;
    const filtro = email ? { user_email: String(email).trim().toLowerCase() } : {};

    const docs = await db.collection('mediciones').find(filtro).toArray();
    const mediciones = docs.map((item) => {
      const id = String(item._id || item.id || '');
      return { ...item, id, _id: id };
    });

    return res.status(200).json({ status: 'success', data: mediciones });
  } catch (error) {
    return res.status(200).json({ status: 'error', message: error.message, data: [] });
  }
});

app.post('/api/mediciones', async (req, res) => {
  try {
    const { tipo_medicion, valor, unidad, notas, fecha_hora } = req.body || {};
    if (!tipo_medicion || !valor || !unidad) {
      return res.status(422).json({ status: 'error', message: 'tipo_medicion, valor y unidad son obligatorios.' });
    }

    const email = req.headers['x-user-email'] || req.body.user_email || null;
    const now = ahoraDateTime();

    const data = {
      user_email: email ? String(email).trim().toLowerCase() : null,
      tipo_medicion: String(tipo_medicion),
      valor: String(valor),
      unidad: String(unidad),
      notas: notas || 'Sin notas',
      fecha_hora: fecha_hora || now,
      created_at: now,
      updated_at: now
    };

    const db = getDB();
    const result = await db.collection('mediciones').insertOne(data);
    const stringId = String(result.insertedId);

    return res.status(201).json({
      status: 'success',
      message: 'Medición registrada correctamente',
      data: { ...data, id: stringId, _id: stringId }
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Error al guardar la medición: ' + error.message
    });
  }
});

app.delete('/api/mediciones/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const email = req.headers['x-user-email'] || req.query.user_email;

    const filtro = filtroIdMongo(id);
    if (email) filtro.user_email = String(email).trim().toLowerCase();

    const db = getDB();
    const result = await db.collection('mediciones').deleteOne(filtro);

    return res.status(200).json({
      status: 'success',
      message: 'Medición eliminada correctamente',
      deleted_count: result.deletedCount
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Error al eliminar la medición: ' + error.message
    });
  }
});

// ==========================================
// 6. EVENTOS Y CITAS
// ==========================================

app.get('/api/eventos', async (req, res) => {
  try {
    const db = getDB();
    const eventos = await db.collection('eventos').find({}).toArray();
    return res.json(eventos);
  } catch (_) {
    return res.json([]);
  }
});

app.post('/api/eventos', async (req, res) => {
  try {
    const { titulo, descripcion, tipo } = req.body || {};
    if (!titulo || !descripcion || !tipo) {
      return res.status(422).json({ mensaje: 'titulo, descripcion y tipo son obligatorios.' });
    }

    const email = resolverEmail(req);
    const nuevoEvento = {
      usuario_id: String(email),
      titulo: String(titulo),
      descripcion: String(descripcion),
      tipo: String(tipo),
      estado: 'pendiente',
      fecha: new Date().toISOString()
    };

    const db = getDB();
    await db.collection('eventos').insertOne({ ...nuevoEvento });

    return res.json({
      mensaje: 'Evento guardado exitosamente en MongoDB Atlas',
      evento: nuevoEvento
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al guardar evento', error: error.message });
  }
});

// ==========================================
// 7. NOTIFICACIONES (CRUD)
// ==========================================

app.get('/api/notificaciones', async (req, res) => {
  let notificaciones = [];

  try {
    const db = getDB();
    notificaciones = await db.collection('notificaciones').find({}).toArray();

    if (!notificaciones || notificaciones.length === 0) {
      notificaciones = [
        {
          id: '1',
          _id: '1',
          titulo: 'Recordatorio de medicamento',
          mensaje: 'Es hora de tomar tu Metformina 500mg con un vaso de agua.',
          tipo: 'recordatorio',
          leida: false,
          fecha: new Date().toISOString()
        },
        {
          id: '2',
          _id: '2',
          titulo: 'Medición de presión estable',
          mensaje: 'Tu última lectura de presión arterial estuvo dentro del rango normal.',
          tipo: 'alerta',
          leida: true,
          fecha: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
        }
      ];
    }
  } catch (_) {
    notificaciones = [];
  }

  return res.json(notificaciones);
});

app.delete('/api/notificaciones/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = getDB();
    const condiciones = [{ id }, { _id: id }];
    if (ObjectId.isValid(id) && id.length === 24) {
      condiciones.push({ _id: new ObjectId(id) });
    }
    await db.collection('notificaciones').deleteMany({ $or: condiciones });
  } catch (_) {}

  return res.json({ mensaje: 'Notificación eliminada exitosamente' });
});

// ==========================================
// 8. CONTACTOS DE EMERGENCIA (CRUD)
// ==========================================

app.get('/api/contactos', async (req, res) => {
  const email = resolverEmail(req);
  let contactos = [];

  try {
    const db = getDB();
    let userDb = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });
    if (!userDb || !userDb.contactos_emergencia) {
      userDb = await db.collection('usuarios').findOne({});
    }
    contactos = userDb?.contactos_emergencia || [];
  } catch (_) {
    contactos = [
      { id: '1', nombre: 'María González', relacion: 'Hija', telefono: '3312345678' },
      { id: '2', nombre: 'Dr. Carlos Silva', relacion: 'Médico Familiar', telefono: '3398765432' }
    ];
  }

  if (typeof contactos === 'string') {
    try {
      contactos = JSON.parse(contactos);
    } catch (_) {
      contactos = [];
    }
  }

  return res.json(Array.isArray(contactos) ? contactos : []);
});

app.post('/api/contactos', async (req, res) => {
  const { nombre, relacion, telefono } = req.body || {};
  if (!nombre || !relacion || !telefono) {
    return res.status(422).json({ mensaje: 'nombre, relacion y telefono son obligatorios.' });
  }

  const email = resolverEmail(req);
  const nuevoContacto = {
    id: crypto.randomBytes(8).toString('hex'),
    nombre: String(nombre),
    relacion: String(relacion),
    telefono: String(telefono)
  };

  try {
    const db = getDB();
    const userDb = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });

    if (!userDb) {
      await db.collection('usuarios').insertOne({
        email,
        nombre: 'Usuario Admin',
        contactos_emergencia: [nuevoContacto]
      });
    } else {
      const contactosActuales = Array.isArray(userDb.contactos_emergencia) ? userDb.contactos_emergencia : [];
      contactosActuales.push(nuevoContacto);
      await db.collection('usuarios').updateOne(
        { $or: [{ email }, { correo: email }] },
        { $set: { contactos_emergencia: contactosActuales } }
      );
    }
  } catch (_) {}

  return res.json({
    mensaje: 'Contacto de emergencia guardado con éxito',
    contacto: nuevoContacto
  });
});

app.put('/api/contactos/:id', async (req, res) => {
  const { nombre, relacion, telefono } = req.body || {};
  if (!nombre || !relacion || !telefono) {
    return res.status(422).json({ mensaje: 'nombre, relacion y telefono son obligatorios.' });
  }

  const email = resolverEmail(req);
  const { id } = req.params;

  try {
    const db = getDB();
    const userDb = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });
    if (userDb && Array.isArray(userDb.contactos_emergencia)) {
      const actualizados = userDb.contactos_emergencia.map((c) => {
        if (String(c.id || '') === id || String(c._id || '') === id) {
          return { ...c, nombre: String(nombre), relacion: String(relacion), telefono: String(telefono) };
        }
        return c;
      });
      await db.collection('usuarios').updateOne(
        { $or: [{ email }, { correo: email }] },
        { $set: { contactos_emergencia: actualizados } }
      );
    }
  } catch (_) {}

  return res.json({ mensaje: 'Contacto actualizado con éxito' });
});

app.delete('/api/contactos/:id', async (req, res) => {
  const email = resolverEmail(req);
  const { id } = req.params;

  try {
    const db = getDB();
    const userDb = await db.collection('usuarios').findOne({ $or: [{ email }, { correo: email }] });
    if (userDb && Array.isArray(userDb.contactos_emergencia)) {
      const filtrados = userDb.contactos_emergencia.filter(
        (c) => String(c.id || '') !== id && String(c._id || '') !== id
      );
      await db.collection('usuarios').updateOne(
        { $or: [{ email }, { correo: email }] },
        { $set: { contactos_emergencia: filtrados } }
      );
    }
  } catch (_) {}

  return res.json({ mensaje: 'Contacto eliminado con éxito' });
});

// ==========================================
// 9. MEDICAMENTOS (CRUD)
// ==========================================

app.get('/api/medicamentos', async (req, res) => {
  try {
    const email = req.headers['x-user-email'] || req.query.user_email;
    const db = getDB();
    const filtro = email ? { user_email: String(email).trim().toLowerCase() } : {};

    const docs = await db.collection('medicamentos').find(filtro).toArray();
    const medicamentos = docs.map((item) => {
      const id = String(item._id || item.id || '');
      return { ...item, id, _id: id };
    });

    return res.status(200).json({ status: 'success', data: medicamentos });
  } catch (error) {
    return res.status(200).json({ status: 'error', message: error.message, data: [] });
  }
});

app.post('/api/medicamentos', async (req, res) => {
  try {
    const { nombre, dosis, unidad, instrucciones, frecuencia, dias, horas, fecha_inicio, fecha_fin } = req.body || {};
    if (!nombre || !dosis || !Array.isArray(horas)) {
      return res.status(422).json({ status: 'error', message: 'nombre, dosis y horas (array) son obligatorios.' });
    }

    const email = req.headers['x-user-email'] || req.body.user_email || null;
    const now = ahoraDateTime();

    const data = {
      user_email: email ? String(email).trim().toLowerCase() : null,
      nombre: String(nombre),
      dosis: String(dosis),
      unidad: unidad || 'tableta(s)',
      instrucciones: instrucciones || 'Sin indicaciones',
      frecuencia: frecuencia || 'Diario',
      dias: Array.isArray(dias)
        ? dias
        : ['lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado', 'domingo'],
      horas: formatearHoras(horas),
      fecha_inicio: fecha_inicio || null,
      fecha_fin: fecha_fin || null,
      created_at: now,
      updated_at: now
    };

    const db = getDB();
    const result = await db.collection('medicamentos').insertOne(data);
    const stringId = String(result.insertedId);

    return res.status(201).json({
      status: 'success',
      message: 'Medicamento guardado correctamente',
      data: { ...data, id: stringId, _id: stringId }
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Error al guardar el medicamento: ' + error.message
    });
  }
});

app.put('/api/medicamentos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const email = req.headers['x-user-email'] || req.body.user_email;
    const { nombre, dosis, unidad, instrucciones, frecuencia, dias, horas, fecha_inicio, fecha_fin } = req.body || {};

    const updates = { updated_at: ahoraDateTime() };
    if (nombre !== undefined) updates.nombre = String(nombre);
    if (dosis !== undefined) updates.dosis = String(dosis);
    if (unidad !== undefined) updates.unidad = unidad;
    if (instrucciones !== undefined) updates.instrucciones = instrucciones;
    if (frecuencia !== undefined) updates.frecuencia = frecuencia;
    if (Array.isArray(dias)) updates.dias = dias;
    if (Array.isArray(horas)) updates.horas = formatearHoras(horas);
    if (fecha_inicio !== undefined) updates.fecha_inicio = fecha_inicio;
    if (fecha_fin !== undefined) updates.fecha_fin = fecha_fin;

    const filtro = filtroIdMongo(id);
    if (email) filtro.user_email = String(email).trim().toLowerCase();

    const db = getDB();
    await db.collection('medicamentos').updateOne(filtro, { $set: updates });

    const item = await db.collection('medicamentos').findOne(filtroIdMongo(id));
    let respuestaItem;
    if (item) {
      const stringId = String(item._id || item.id || id);
      respuestaItem = { ...item, id: stringId, _id: stringId };
    } else {
      respuestaItem = { id: String(id), _id: String(id), ...updates };
    }

    return res.status(200).json({
      status: 'success',
      message: 'Medicamento actualizado correctamente',
      data: respuestaItem
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Error al actualizar el medicamento: ' + error.message
    });
  }
});

app.delete('/api/medicamentos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const email = req.headers['x-user-email'] || req.query.user_email;

    const filtro = filtroIdMongo(id);
    if (email) filtro.user_email = String(email).trim().toLowerCase();

    const db = getDB();
    const result = await db.collection('medicamentos').deleteOne(filtro);

    return res.status(200).json({
      status: 'success',
      message: 'Medicamento eliminado correctamente',
      deleted_count: result.deletedCount
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Error al eliminar el medicamento: ' + error.message
    });
  }
});

// ==========================================
// 10. CHAT MÉDICO EN VIVO
// ==========================================

app.get('/api/chat/contactos', async (req, res) => {
  try {
    const emailActual = resolverEmail(req);
    const db = getDB();
    const usuarios = await db.collection('usuarios').find({}, { projection: { password: 0, contrasena: 0 } }).toArray();

    const contactosValidos = usuarios.filter((u) => {
      const e = String(u.email || u.correo || '').trim().toLowerCase();
      return e !== '' && e !== emailActual;
    });

    return res.json(contactosValidos);
  } catch (_) {
    return res.json([]);
  }
});

app.get('/api/chat/conversacion/:receptorEmail', async (req, res) => {
  try {
    const emailActual = resolverEmail(req);
    const receptorEmailLower = String(req.params.receptorEmail || '').trim().toLowerCase();
    const db = getDB();

    const mensajes = await db.collection('mensajes_chat').find({}).toArray();

    const conversacion = mensajes.filter((msg) => {
      const remitente = String(msg.remitente_email || '').trim().toLowerCase();
      const receptor = String(msg.receptor_email || '').trim().toLowerCase();
      return (
        (remitente === emailActual && receptor === receptorEmailLower) ||
        (remitente === receptorEmailLower && receptor === emailActual)
      );
    });

    return res.json(conversacion);
  } catch (_) {
    return res.json([]);
  }
});

app.post('/api/chat/enviar', async (req, res) => {
  try {
    const { receptor_email, mensaje } = req.body || {};
    if (!receptor_email || !mensaje) {
      return res.status(422).json({ mensaje: 'receptor_email y mensaje son obligatorios.' });
    }

    const emailActual = resolverEmail(req);
    const receptorLower = String(receptor_email).trim().toLowerCase();
    const db = getDB();

    const receptorDb = await db.collection('usuarios').findOne({ $or: [{ email: receptorLower }, { correo: receptorLower }] });
    if (!receptorDb) {
      return res.status(422).json({
        mensaje: 'El usuario destinatario ya no cuenta con cuenta activa en el sistema.'
      });
    }

    const remitenteDb = await db.collection('usuarios').findOne({ $or: [{ email: emailActual }, { correo: emailActual }] });
    const nombreActual = remitenteDb?.nombre || remitenteDb?.name || req.body.remitente || 'Usuario';

    const nuevoMensaje = {
      id: crypto.randomBytes(8).toString('hex'),
      remitente_email: emailActual,
      receptor_email: receptorLower,
      remitente: nombreActual,
      mensaje: String(mensaje),
      fecha: new Date().toISOString()
    };

    await db.collection('mensajes_chat').insertOne({ ...nuevoMensaje });

    return res.json({
      mensaje: 'Mensaje enviado exitosamente',
      datos: nuevoMensaje
    });
  } catch (error) {
    return res.status(500).json({ mensaje: 'Error al enviar mensaje', error: error.message });
  }
});

// ==========================================
// RUTA BASE E INICIO DEL SERVIDOR
// ==========================================

app.get('/', (req, res) => {
  res.json({ status: 'ok', servicio: 'Pulso API Express' });
});

connectDB()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`API Pulso corriendo en http://0.0.0.0:${PORT}/api`);
    });
  })
  .catch((err) => {
    console.error('Error al conectar con MongoDB:', err);
    process.exit(1);
  });