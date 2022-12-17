const User = require('../../models/User');
const { ApolloError } = require('apollo-server-errors');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken")

module.exports = {
    Mutation: {
        async registerUser(_, {registerInput: {username, email, password} }) {
            
            const oldUser = await User.findOne({ email });               // Ver si un usuario ya existe en bd con el email 
            
            if( oldUser ){                                               // Gestionar error si el usuario existe
                throw new ApolloError(
                    ' Un usuario ya esta registrado con el email' + email ,'USER_ALREADY_EXISTS'
                )
            }
           
            let encryptedPassword = await bcrypt.hash(password, 10)      // Encryptar la password
            
            const newUser = new User({                                   // Contruir nuestro instancia del nuevo usuario
                username: username,
                email: email.toLowerCase(),
                password: encryptedPassword
            })
            
            const token = jwt.sign(                                      // Crear nuestro JWT 
                { user_id: newUser._id, email },                         // Usamos el id de usuario generado por mongoose,
                "UNSAFE_STRING",                                         // un palabra secreta de encriptación
                { expiresIn: "2h" }                                      // y el tiempo de duración del token    
            );

            newUser.token = token;                                       // Le damos valor al campo token del usuario con el valor generado.
            
            const res = await newUser.save()                             // Grabar nuestro usuario en la base de datos MongoDB

            return{
                id: res.id,
                ...res._doc
            };
        },
        async loginUser(_, { loginInput: { email, password }}){
            
            const user = await User.findOne({ email });                         // Vemos si existe un usuario con el email del inputs
            
            if(user && (await bcrypt.compare( password, user.password ))){      // Comprobamos si la password del input = a la pass encryptada
                const token = jwt.sign(                                         // Creamos nuestro JWT 
                    { user_id: user._id, email },                               // Usamos el id de usuario generado por mongoose,
                    "UNSAFE_STRING",                                            // un palabra secreta de encriptación
                    { expiresIn: "2h" }                                         // y el tiempo de duración del token    
                );

                user.token = token;                                             // Le damos valor al campo token del usuario con el valor generado
            

            return { 
                id: user.id,
                ...user._doc
            }

            
            } else {
                throw new ApolloError('Incorrect password', 'INCORRECT_PASSWORD') // Si el usuario no existe return el error.
            }
        }
    },
    Query: {
            user: (_, {ID}) => User.findById(ID)
    }   
}