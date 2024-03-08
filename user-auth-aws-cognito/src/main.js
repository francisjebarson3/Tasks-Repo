const {router} = require('./routes/user.routes');
const {express} = require('./utils/expressUtils');
const dotenv = require( 'dotenv');
const app = express();
dotenv.config();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = process.env.PORT;
app.use("/users", router);

app.listen(PORT, () => {
    console.log(`Server is up and running at ${PORT}`);
});


