// frontend/lib/utils.ts
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Função utilitária de Tailwind (para unir classes dinamicamente).
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Base da API (usando variável de ambiente ou padrão localhost).
 * Exemplo para .env.local:
 * NEXT_PUBLIC_API_BASE=http://127.0.0.1:8000
 */
export const API_BASE =
  (typeof window !== "undefined" && process.env.NEXT_PUBLIC_API_BASE) ||
  "172.25.48.1:8000";

/**
 * Função padrão de requisições JSON autenticadas.
 * - Garante headers e token JWT.
 * - Evita erro de URL duplicada.
 * - Trata respostas 4xx/5xx com erro legível.
 */
export async function fetchJSON(path: string, options: RequestInit = {}) {
  if (!path) throw new Error("fetchJSON: caminho da requisição não informado.");

  // Garante que não haja duplicação de host (corrige o erro anterior)
  const cleanPath = path.startsWith("http")
    ? path
    : `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;

  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  try {
    const res = await fetch(cleanPath, { ...options, headers });

    if (!res.ok) {
      const text = await res.text();
      console.error(`[fetchJSON] Erro HTTP ${res.status}:`, text);
      throw new Error(text || `HTTP ${res.status}`);
    }

    // Retorna JSON parseado
    return res.json();
  } catch (err: any) {
    console.error(`[fetchJSON] Falha ao buscar ${cleanPath}:`, err.message);
    throw err;
  }
}
