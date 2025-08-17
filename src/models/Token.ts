



const tokenSchema = Schema = new Schema({
    token: {
        type: String,
        required: true
    },
    user: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        default: Date.now(),
        expires: '5m',
    }
});

const Token = model('Token', tokenSchema);

export default Token;