import { IncomingForm } from "formidable";
import userModel from "../../Models/User/User";
import Bcrypt from "bcrypt";

class AuthController {
  SignUp(request, response) {
    const form = new IncomingForm();

    try {
      form.parse(request, async (error, fields, files) => {
        if (error) {
          return response
            .status(500)
            .json({ msg: "Server Failed to pass request" });
        }

        const { username, password } = fields;

        if (!username || !password) {
          return response.status(400).json({ msg: "All fields are required" });
        }

        const isExistingUser = await userModel.findOne({ username: username });

        if (isExistingUser) {
          return response
            .status(400)
            .json({ msg: "Account with this username already exist" });
        }

        const salt = await Bcrypt.genSalt(15);
        const hashedPassword = await Bcrypt.hash(password, salt);

        const newUser = new userModel({
          username,
          password: hashedPassword,
        });
        const savedUser = await newUser.save();
        return response.status(201).json(savedUser);
      });
    } catch (error) {
      return response
        .status(500)
        .json({ msg: "Server currently down pleasse try again later" });
    }
  }
  SignIn(request, response) {
    const form = new IncomingForm();

    try {
      form.parse(request, async (error, fields, files) => {
        if (error) {
          return response
            .status(500)
            .json({ msg: "Server Failed to parse request" });
        }
        const { username, password } = fields;

        if (!username || !password) {
          return response.status(400).json({ msg: "All fields are required" });
        }

        const user = await userModel.findOne({ username: username });

        if (!user) {
          return response
            .status(404)
            .json({ msg: "Account with this username does not exist" });
        }

        const hashedPassword = user.password;
        const isPasswordValid = await Bcrypt.compare(password, hashedPassword);

        if (!isPasswordValid) {
          return response.status(400).json({ msg: "Passwor is invalid" });
        }

        return response.status(200).json({ msg: "You are logged in" });
      });
    } catch (error) {
      return response
        .status(500)
        .json({ msg: "Server is currently down please try again" });
    }
  }
}

export default AuthController;
