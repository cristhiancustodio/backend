import app from "./server"



const port = process.env.PORT || 4000

app.listen(port, () => {
    console.log(`REST API funcionando en el puerto ${port}`)
})