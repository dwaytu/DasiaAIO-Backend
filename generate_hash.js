const bcrypt = require('bcryptjs');

(async () => {
  try {
    const hash = await bcrypt.hash('user123', 10);
    console.log(hash);
  } catch (err) {
    console.error(err);
  }
})();
