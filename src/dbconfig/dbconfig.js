import mongoose from "mongoose";

export async function connect(){
    try{
       await mongoose.connect(process.env.MONGODB_URI);

        const connection=mongoose.connection;
        connection.on('connected',()=>{
            console.log("DB Connected");
        })

         connection.on('error',()=>{
            console.log("Error Occured At DB Connection");
            process.exit();
        })


    }catch(e){
        console.log("Something Wrong",e);
    }

}