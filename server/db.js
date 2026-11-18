import mongoose from 'mongoose';

// User accounts, persisted in MongoDB Atlas.
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    verified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});

export const User = mongoose.model('User', userSchema);

export async function connectDB() {
    const uri = process.env.MONGODB_URI;
    if (!uri) {
        console.error('[db] MONGODB_URI is not set — accounts will not be saved.');
        return;
    }
    try {
        await mongoose.connect(uri, {
            dbName: process.env.DB_NAME || 'drivefusion',
            serverSelectionTimeoutMS: 8000, // fail fast instead of hanging requests
        });
        console.log('[db] MongoDB connected');
    } catch (err) {
        console.error('[db] MongoDB connection error:', err.message);
    }
}

// true once Mongoose has an active connection (readyState 1 = connected)
export function isDbConnected() {
    return mongoose.connection.readyState === 1;
}
