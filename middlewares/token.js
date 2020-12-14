const jwt = require('jsonwebtoken')


let tokenAuth = (req, res, next) => {
 if(req.headers.authorization!==undefined){
    jwt.verify(req.headers.authorization, process.env.TOKEN_PASS, (err, decoded) => {
        if (err) throw (res.status(404).json({
            message:'Session over, login again'
        }))
        console.log(decoded)
    })
    next()
 }
 else{
     res.status(404).json({
         message:"token not authorized"
     })
 }
}

module.exports = tokenAuth