import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bodyParser from 'body-parser';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const SERVER = express();
SERVER.use(express.json());
SERVER.use(cors());

const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
            cb(null, true);
        } else {
            cb(new Error('Formato file non supportato'), false);
        }
    }
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

userSchema.methods.comparePassword = function (enteredPassword) {
    return bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

const formDataSchema = new mongoose.Schema({
    img: String,
    titolo: String,
    desc: String,
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, {
    versionKey: false
});

const FormData = mongoose.model('Post', formDataSchema);

SERVER.use(bodyParser.urlencoded({ extended: true }));
SERVER.use(bodyParser.json());

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Accesso negato, token mancante' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token non valido o scaduto' });
        req.user = user;
        next();
    });
};

SERVER.post('/Blog/posts', authenticateToken, upload.single('img'), async (req, res) => {
    const { titolo, desc } = req.body;
    const imgBuffer = req.file ? req.file.buffer : null;

    if (imgBuffer) {
        const imgBase64 = imgBuffer.toString('base64');
        try {
            const newFormData = new FormData({
                img: `data:image/jpeg;base64,${imgBase64}`,
                titolo,
                desc,
                authorId: req.user.id
            });

            await newFormData.save();
            res.status(201).send('Post inviato con successo!');
        } catch (err) {
            console.error('Errore durante il salvataggio del post:', err);
            res.status(500).send('Errore nel salvataggio del post');
        }
    } else {
        res.status(400).send('Nessuna immagine ricevuta');
    }
});

SERVER.get('/Blog/posts', async (req, res) => {
    try {
        const posts = await FormData.find();
        if (!posts || posts.length === 0) {
            return res.status(404).json({ message: 'Nessun post trovato' });
        }
        res.json(posts);
    } catch (err) {
        console.error('Errore durante il recupero dei post:', err);
        res.status(500).json({ message: 'Errore interno del server', error: err.message });
    }
});

SERVER.put('/Blog/posts/:id', authenticateToken, upload.single('img'), async (req, res) => {
    const postId = req.params.id;
    const { titolo, desc } = req.body;
    const imgBuffer = req.file ? req.file.buffer : null;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ message: 'ID del post non valido' });
    }

    try {
        const post = await FormData.findById(postId);
        if (!post) return res.status(404).json({ message: 'Post non trovato' });

        if (post.authorId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Non puoi modificare questo post' });
        }

        post.titolo = titolo || post.titolo;
        post.desc = desc || post.desc;

        if (imgBuffer) {
            const imgBase64 = imgBuffer.toString('base64');
            post.img = `data:image/jpeg;base64,${imgBase64}`;
        }

        await post.save();
        res.json({ message: 'Post aggiornato con successo' });

    } catch (err) {
        console.error('Errore durante l\'aggiornamento del post:', err);
        res.status(500).json({ message: 'Errore interno del server', error: err.message });
    }
});

SERVER.delete('/Blog/posts/:id', authenticateToken, async (req, res) => {
    const postId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
        return res.status(400).json({ message: 'ID del post non valido' });
    }

    try {
        const post = await FormData.findById(postId);
        if (!post) return res.status(404).json({ message: 'Post non trovato' });

        if (!post.authorId.equals(req.user.id)) {
            return res.status(403).json({ message: 'Non puoi eliminare questo post' });
        }

        await FormData.deleteOne({ _id: postId });
        res.json({ message: 'Post eliminato con successo' });
    } catch (error) {
        console.error('Errore durante la cancellazione del post:', error);
        res.status(500).json({ message: 'Errore interno del server', error: error.message });
    }
});

SERVER.listen(3001, () => {
    console.log('Server in ascolto sulla porta 3001');
});

mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log("Connesso a MongoDB");
    })
    .catch((err) => {
        console.error("Errore nella connessione a MongoDB:", err);
    });


    //end