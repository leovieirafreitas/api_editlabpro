require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const app = express();

// Configurações do servidor
const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'chave-secreta-padrao-super-segura-123';

// Cliente Supabase (com papel de Service Role para ignorar RLS e gerenciar Auth livremente se precisar)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Middlewares
app.use(cors()); // Permite requisições de qualquer lugar (o DaVinci/Premiere precisa disso)
app.use(express.json()); // Habilita o parsing de JSON no corpo da requisição

// Rota de Teste Simples
app.get('/health', (req, res) => {
    res.json({ status: 'ok', message: 'API EditLab Pro está rodando!' });
});

// Resposta para a raiz (evitar erro 404/502 no navegador vazio)
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'EditLab Pro API Server Ligado e Operante!' });
});

// ----------------------------------------------------------------------
// ROTA: LOGIN
// ----------------------------------------------------------------------
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    }

    try {
        // Usa o Supabase para validar email/senha
        const { data, error } = await supabase.auth.signInWithPassword({
            email: email,
            password: password
        });

        if (error) {
            return res.status(401).json({ error: 'Credenciais inválidas ou e-mail não cadastrado.' });
        }

        // Se o login der sucesso, criamos um token JWT exclusivo e seguro que seu plugin vai usar
        const user = data.user;
        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '30d' } // O token do usuário será válido por 30 dias na máquina dele
        );

        res.json({
            message: 'Login bem-sucedido!',
            user: { id: user.id, email: user.email },
            token: accessToken // O plugin do painel deve salvar esse Token (no localStorage)
        });

    } catch (err) {
        res.status(500).json({ error: 'Falha no servidor ao tentar conectar com a base.' });
    }
});

// ----------------------------------------------------------------------
// MIDDLEWARE DE AUTENTICAÇÃO (Para proteger rotas de Músicas/SFX/Vídeos)
// ----------------------------------------------------------------------
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Token de acesso ausente. Faça login novamente.' });
    }

    const token = authHeader.split(' ')[1]; // formato: "Bearer <token>"
    if (!token) {
        return res.status(401).json({ error: 'Token mal formatado.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Salva os dados do usuário na requisição
        next(); // Autoriza a execução da rota protegida
    } catch (err) {
        return res.status(403).json({ error: 'Token inválido ou expirado. Faça login novamente.' });
    }
}

// ----------------------------------------------------------------------
// ROTA PROTEGIDA DA BIBLIOTECA (Proxy Seguro para o Banco de Dados)
// ----------------------------------------------------------------------
const ALLOWED_TABLES = ['music_library', 'sfx_library', 'filmes_cortes', 'view_filmes_unicos'];

app.get('/api/db/:table', requireAuth, async (req, res) => {
    const table = req.params.table;
    if (!ALLOWED_TABLES.includes(table)) {
        return res.status(403).json({ error: 'Acesso à tabela negado.' });
    }

    try {
        const queryParams = new URLSearchParams(req.query).toString();
        const targetUrl = `${SUPABASE_URL}/rest/v1/${table}?${queryParams}`;

        const fetchRes = await fetch(targetUrl, {
            headers: {
                'apikey': SUPABASE_SERVICE_ROLE_KEY,
                'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
                'Accept': req.headers.accept || 'application/json',
                'Prefer': req.headers.prefer || ''
            }
        });

        const data = await fetchRes.text();
        const range = fetchRes.headers.get('content-range');
        if (range) {
            res.setHeader('Access-Control-Expose-Headers', 'Content-Range');
            res.setHeader('Content-Range', range);
        }
        res.status(fetchRes.status).send(data);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Iniciando o servidor
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor EditLab Pro rodando na porta ${PORT}`);
});
