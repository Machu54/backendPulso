const { MongoClient } = require('mongodb');
require('dotenv').config();

const uri = process.env.DB_URI || process.env.MONGO_URI;
const dbName = process.env.DB_DATABASE || process.env.DB_NAME || 'pulso_db';

let client = null;
let db = null;

async function connectDB() {
  if (db) return db;
  if (!uri) {
    throw new Error('Falta definir DB_URI en el archivo .env');
  }
  client = new MongoClient(uri);
  await client.connect();
  db = client.db(dbName);
  console.log(`Conectado a MongoDB Atlas -> Base de datos: ${dbName}`);
  return db;
}

function getDB() {
  if (!db) {
    throw new Error('La conexión a MongoDB aún no está inicializada.');
  }
  return db;
}

module.exports = { connectDB, getDB };