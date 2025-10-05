import { all } from './db.js';
import fs from 'fs';

(async () => {
  try {
    const users = await all('SELECT id, full_name, dob, nid, license, email, phone, created_at FROM users');
    const police = await all('SELECT id, full_name, police_id, nid, email, phone, created_at FROM police_officers');
    const violations = await all('SELECT * FROM violations');

    const snapshot = { timestamp: new Date().toISOString(), users, police_officers: police, violations };
    console.log(JSON.stringify(snapshot, null, 2));
    fs.writeFileSync('db_snapshot.json', JSON.stringify(snapshot, null, 2));
    console.log('\nSnapshot written to db_snapshot.json');
  } catch (e) {
    console.error('Error inspecting database:', e);
  } finally {
    process.exit(0);
  }
})();
