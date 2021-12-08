const express = require("express");

const cors = require("cors");

const jwt = require("jsonwebtoken");

const mongoose = require("mongoose");

const bcrypt = require("bcrypt");

const cfn = require("./config");
//const { jwt_expires } = require("./config");

const url = "mongodb+srv://thiagoprado:vaicurintia1910@clustername.fpofj.mongodb.net/segundaapi?retryWrites=true&w=majority";

mongoose.connect(url, {useNewUrlParser:true, useUnifiedTopology:true });

const tabela = mongoose.Schema({
    nome:{type:String, required:true},
    email:{type:String, required:true, unique:true},
    usuario:{type:String, required:true, unique:true},
    senha:{type:String, required:true}
});

tabela.pre("save",function(next){
    let usuario = this;
    if(!usuario.isModified('senha')) return next()
    bcrypt.hash(usuario.senha,10,(erro,rs)=>{
        if(erro) return console.log(`erro ao gerar senha ->${erro}`);
        usuario.senha = rs;
        return next();
    }) 
})

const Usuario = mongoose.model("tbusuario",tabela);

const app = express();
app.use(cors());

app.use(express.json());



app.post("/api/usuario/cadastro",(req,res)=>{

    const usuario = new Usuario(req.body);
    usuario.save().then((rs)=>{
        //const gerado = criaToken(req.body.usuario,req.body.nome);
        res.status(201).send({output:`Usuário cadastrado`,payload:rs});
    })
    .catch((err)=>res.status(400).send({output:`Erro ao tentar cadastradar o usuário`,texto:err}))
});



app.get("/api/usuario/:id",(req,res)=>{
    Usuario.findById(req.params.id,(erro,dados)=>{
        if(erro){
            return res.status(400).send({output:`Erro ao tentar ler os usuarios -> ${erro}`});
        }
        res.status(200).send({output:dados});
    }

    );
});





app.post("/api/usuario/login",(req,res)=>{
    const us = req.body.usuario;
    const sh = req.body.senha;
    Usuario.findOne({usuario:us},(erro,dados)=>{
        if(erro){
            return res.status(400).send({output:`Usuário não localizado->${erro}`});
        }
        bcrypt.compare(sh,dados.senha,(erro,igual)=>{
            if(erro) return res.status(400).send({output:`Erro ao tentar logar->${erro}`});
            if(!igual) return res.status(400).send({output:`Erro ao tentar logar->${erro}`});
            // const gerado = criaToken(dados.usuario,dados.nome);
            res.status(200).send({output:`Logado`,payload:dados});
        })
    });
});




app.get("/api/usuario/", verifica,(req,res)=>   {
    Usuario.find((erro,dados)=>{
        if(erro){
            return res.status(400).send({output:`Erro ao tentar ler os usuário -> ${erro}`});
        }
        res.status(200).send({output:dados});
    }

    );
});


app.put("/api/usuario/atualizar/:id",(req,res)=>{
    Usuario.findByIdAndUpdate(req.params.id,req.body,(erro,dados)=>{
        if(erro){
            return res.status(400).send({output:`Erro ao tentar atualizar -> ${erro}`});
        }
        res.status(200).send({output:`Dados atualizados`});
    })
});

app.delete("/api/usuario/apagar/:id", verifica,(req,res)=>{
    Usuario.findByIdAndDelete(req.params.id,(erro,dados)=> {
        if(erro){
            return res.status(400).send({output:`Erro ao tentar apagar o usuário -> ${erro}`});
        }
        res.status(204).send({});
    })
});

const criaToken=(usuario, nome)=>{
    return jwt.sign({usuario:usuario,nome:nome},cfn.jwt_key,{expiresIn:cfn.jwt_expires});
};


function verifica (req,res,next){
    const token_gerado = req.headers.token;
    if(!token_gerado){
        return res.status(401).send({output:"Não há token"});
    }
    jwt.verify(token_gerado,cfn.jwt_key,(erro,dados)=>{
        if(erro){
            return res.status(401).send({output:"Token inválido"});
        }
        next();
    });
};


app.listen(3000,()=>console.log("Servidor online em http://localhost:3000"));
