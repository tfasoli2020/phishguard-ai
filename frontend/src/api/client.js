import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

export const analyzeEmail = (emailText) =>
  api.post('/analyze', { email_text: emailText }).then((r) => r.data)

export const getHistory = (limit = 50) =>
  api.get('/history', { params: { limit } }).then((r) => r.data)

export const getAnalysis = (id) =>
  api.get(`/history/${id}`).then((r) => r.data)

export const deleteAnalysis = (id) =>
  api.delete(`/history/${id}`)

export const getHealth = () =>
  api.get('/health').then((r) => r.data)
