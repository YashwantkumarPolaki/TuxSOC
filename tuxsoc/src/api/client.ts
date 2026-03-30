import axios from 'axios'

// No trailing slash — FastAPI is strict about this
export const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000').replace(/\/$/, '')

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 10000,
  // Do NOT set a global Content-Type here.
  // For JSON requests Axios sets it automatically.
  // For multipart/form-data (file uploads) the browser must set it
  // so it can include the required boundary string — if we force
  // 'application/json' here it breaks all file uploads with a 422.
})

// Intercept — tag network errors so callers can distinguish them
apiClient.interceptors.response.use(
  res => res,
  err => {
    err.isNetworkError = !err.response
    return Promise.reject(err)
  }
)

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await apiClient.get('/health', { timeout: 3000 })
    return res.data?.status === 'healthy'
  } catch {
    return false
  }
}
