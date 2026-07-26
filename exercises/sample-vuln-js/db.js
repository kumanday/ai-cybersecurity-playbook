// Data layer for the intentionally vulnerable training app. See server.js
// header: this file exists so the path audit can trace a sink across files.

function getConn() {
  // Placeholder for a real driver (sqlite3, pg, mysql2); the training
  // exercises are static, so the connection object only needs to exist.
  return { query: (sql) => Promise.resolve({ rows: [], sql }) };
}

// VULN (A03): SQL injection. `name` comes straight from req.query in
// server.js and lands in the query through string concatenation.
async function findUsers(name) {
  const conn = getConn();
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  return conn.query(sql);
}

module.exports = { findUsers };
