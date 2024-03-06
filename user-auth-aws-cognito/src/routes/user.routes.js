const {express} = require('../utils/expressUtils');
const router = express.Router();
const { login, verifyBearerToken, signup } = require('../controller/user.controller');

// Routes
router.post('/login', async (req, res) => {
  const resp = await login(req, res);
  res.send(resp);
});

router.post('/verify', async (req, res) => {
  const resp = await verifyBearerToken(req, res);
  res.send(resp);
});

router.post('/signup', async (req, res) => {
  const resp = await signup(req, res);
  res.send(resp);
});

module.exports = {router};