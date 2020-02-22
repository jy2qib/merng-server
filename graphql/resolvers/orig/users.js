const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { UserInputError } = require('apollo-server');

const {
  validateRegisterInput,
  validateLoginInput
} = require('../../util/validators');
const { SECRET_KEY } = require('../../config');
const User = require('../../models/User');

function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      username: user.username
    },
    SECRET_KEY,
    { expiresIn: '1h' }
  );
}

module.exports = {
  Mutation: {
//Validates Login user data ------------------------------------------------------------
        async login(_, { username, password }){
            const { errors, valid } = validateLoginInput(username, password);
            if(!valid){   //valid > validators.js
                throw new UserInputError('Errors', { errors });
            }

            const user = await User.findOne({ username });   //User > typeDes.js
            if(!user){
                errors.general = 'User not found';
                throw new UserInputError('User not found', { errors });
            }

            const match = await bcrypt.compare(password, user.password);
            if(!match){
                errors.general = 'Wrong credentials';
                throw new UserInputError('Wrong credentials', { errors });
            }

            const token = generateToken(user);
            return {
                ...user._doc,
                id: user._id,
                token
            };
        },
        async register(
            _, 
            { 
                registerInput: { username, email, password, confirmPassword }
            }, 
            ) {
//Validates Register user data ------------------------------------------------------------
            const { valid, errors } = validateRegisterInput(
                username, 
                email, 
                password, 
                confirmPassword
            );
            if (!valid) {
                throw new UserInputError('Errors', { errors });
            }

//Checks whether user already exist ----------------------------------------------
            const user = await User.findOne({ username });
            if(user){
                throw new UserInputError('Username is taken', {
                    errors: {
                        username: 'This username is taken'
                    }
                });
            }

//Hash password and create an auth token -----------------------------------
            password = await bcrypt.hash(password, 12);

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            });

            const res = await newUser.save();

            const token = generateToken(res);
            //old token approach. Function created on top
            /* const token = jwt.sign({
                id: res.id,
                email: res.email, 
                username: res.username
            }, SECRET_KEY, { expiresIn: '1h' }); */
            return {
                ...res._doc,
                id: res._id,
                token
            };
        }
    }
}