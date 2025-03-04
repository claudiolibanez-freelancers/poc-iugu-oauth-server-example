import express, { Request, Response } from 'express'
import bodyParser from 'body-parser'
import dotenv from 'dotenv'

dotenv.config()

// Configuração do servidor
const app = express()
const PORT = process.env.PORT || 3333

// Middleware para interpretar requisições JSON e URL-encoded
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/**
 * Interface que representa a resposta de token da API da Iugu.
 *
 * @property {string} access_token - O token de acesso JWT emitido pela Iugu.
 * @property {'Bearer'} token_type - O tipo do token (sempre 'Bearer').
 * @property {number} expires_in - Tempo de expiração do token, em segundos.
 */
interface IuguTokenResponse {
    access_token: string
    token_type: 'Bearer'
    expires_in: number
}

/**
 * Rota POST /auth/iugu
 *
 * Recebe um código de autenticação via body, encaminha uma requisição para a API da Iugu,
 * e retorna o token de acesso recebido.
 *
 * O endpoint espera receber no body um JSON contendo:
 * @example
 * {
 *   "code": "valor_do_code"
 * }
 *
 * Caso o parâmetro code não seja informado, retorna erro 400.
 *
 * Variáveis de ambiente necessárias:
 * - CLIENT_ID: Identificador do cliente para a Iugu.
 * - CLIENT_SECRET: Segredo do cliente para a Iugu.
 * - REDIRECT_URI: URI de redirecionamento configurada na Iugu.
 */
app.post('/auth/iugu', async (req: Request, res: Response) => {
    const { code } = req.body
  
    if (!code) {
      res.status(400).json({ error: 'code is required' })
      return
    }
  
    const clientId = process.env.CLIENT_ID
    const clientSecret = process.env.CLIENT_SECRET
    const redirectUri = process.env.REDIRECT_URI
  
    if (!clientId || !clientSecret || !redirectUri) {
      res.status(500).json({ error: 'Missing CLIENT_ID, CLIENT_SECRET or REDIRECT_URI in environment' })
      return
    }
  
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
  
    const params = new URLSearchParams()
    params.append('grant_type', 'client_credentials')
    params.append('code', code)
    params.append('redirect_uri', redirectUri)
    params.append('client_id', clientId)
  
    try {
      const tokenResponse = await fetch('https://identity.iugu.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`,
        },
        body: params.toString(),
      })
  
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text()
        res.status(tokenResponse.status).json({ error: errorText })
        return
      }
  
      const tokenData = await tokenResponse.json()
      res.status(200).json(tokenData)
    } catch (error: any) {
      res.status(500).json({ error: 'Error connecting to Iugu', details: error.message })
    }
  })

/**
 * Rota POST /auth/verify
 *
 * Esta rota encaminha uma requisição para o endpoint https://identity.iugu.com/verify,
 * verificando se o usuário (ou app) possui as permissões necessárias.
 *
 * O `workspace_id` é definido internamente pelo backend (via variável de ambiente IUGU_WORKSPACE_ID)
 * e não deve ser enviado pelo cliente.
 *
 * Requisitos da requisição:
 *  - Header:
 *      Authorization: Bearer <token>
 *  - Corpo JSON contendo:
 *      - principals: string (ex.: "app:5bBOZ6Sd9hVygakhV9j8Qx")
 *      - actions: string[] (ex.: ["pix:cob.write"])
 *
 * Exemplo de payload:
 * {
 *   "principals": "app:5bBOZ6Sd9hVygakhV9j8Qx",
 *   "actions": ["pix:cob.write"]
 * }
 */
app.post('/auth/verify', async (req: Request, res: Response) => {
  // Verifica se o header Authorization está presente e possui o formato Bearer
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized: Bearer token missing' });
    return;
  }
  const bearerToken = authHeader.split(' ')[1];

  // Extrai os dados do payload (somente principals e actions)
  const { principals, actions } = req.body;
  if (!principals || !actions) {
    res.status(400).json({ error: 'Missing required fields: principals, actions' });
    return;
  }

  // Define o workspace_id internamente pelo backend
  const workspace_id = process.env.IUGU_WORKSPACE_ID;
  if (!workspace_id) {
    res.status(500).json({ error: 'Workspace ID not configured' });
    return;
  }

  try {
    // Chama o endpoint de verify da Iugu com o payload completo
    const verifyResponse = await fetch('https://identity.iugu.com/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${bearerToken}`
      },
      body: JSON.stringify({ workspace_id, principals, actions })
    });

    if (!verifyResponse.ok) {
      const errorText = await verifyResponse.text();
      res.status(verifyResponse.status).json({ error: errorText });
      return;
    }

    const verifyData = await verifyResponse.json();

    console.log(verifyData)

    res.status(200).json(verifyData);
  } catch (error: any) {
    console.log({ error })

    res.status(500).json({ error: 'Error connecting to Iugu', details: error.message });
  }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`)
})