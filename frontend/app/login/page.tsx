// frontend/app/login/page.tsx
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import Link from "next/link";
import { fetchJSON } from "@/lib/utils";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [twoFACode, setTwoFACode] = useState("");
  const [step, setStep] = useState<"login" | "2fa">("login");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const router = useRouter();

  // ===========================
  // 🔐 ETAPA 1 — LOGIN NORMAL
  // ===========================
  const handleLoginStep1 = async () => {
    setError(null);
    setLoading(true);

    try {
      const data = await fetchJSON("/api/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });

      // 🟦 Se precisar de 2FA → abrir tela do código
      if (data.status === "2fa_required") {
        setStep("2fa");
        setLoading(false);
        return;
      }

      // 🟩 Login normal (caso 2FA já confirmado antes)
      // CORREÇÃO: Verificar se o token e username foram retornados
      if (!data.token || !data.username) {
        throw new Error("Dados de autenticação incompletos");
      }

      localStorage.setItem("token", data.token);
      localStorage.setItem("username", data.username);
      
      // CORREÇÃO: Redirecionar apenas se os dados estiverem completos
      router.push("/chat");
    } catch (e: unknown) {
      // CORREÇÃO: Tratamento específico para erro 404 (email não encontrado)
      if (e instanceof Error) {
        if (e.message.includes("404") || e.message.toLowerCase().includes("not found")) {
          setError("Email não cadastrado. Verifique seu email ou crie uma conta.");
        } else if (e.message.includes("400") || e.message.toLowerCase().includes("bad request")) {
          setError("Credenciais inválidas. Verifique seu usuário e senha.");
        } else if (e.message.includes("401") || e.message.toLowerCase().includes("unauthorized")) {
          setError("Senha incorreta. Tente novamente.");
        } else {
          setError(e.message);
        }
      } else {
        setError("Falha no login. Tente novamente.");
      }
    } finally {
      setLoading(false);
    }
  };

  // ===============================
  // 🔑 ETAPA 2 — ENVIAR CÓDIGO 2FA
  // ===============================
  const handleLoginStep2 = async () => {
    setError(null);
    setLoading(true);

    try {
      const data = await fetchJSON("/api/login/2fa", {
        method: "POST",
        body: JSON.stringify({
          username,
          code: twoFACode,
        }),
      });

      // CORREÇÃO: Verificar se o token e username foram retornados
      if (!data.token || !data.username) {
        throw new Error("Dados de autenticação incompletos");
      }

      // sucesso do 2FA → recebeu token!
      localStorage.setItem("token", data.token);
      localStorage.setItem("username", data.username);

      router.push("/chat");
    } catch (e: unknown) {
      // CORREÇÃO: Tratamento específico para erros no 2FA
      if (e instanceof Error) {
        if (e.message.includes("404") || e.message.toLowerCase().includes("not found")) {
          setError("Usuário não encontrado. Verifique suas credenciais.");
        } else if (e.message.includes("400") || e.message.toLowerCase().includes("invalid")) {
          setError("Código 2FA inválido. Tente novamente.");
        } else {
          setError(e.message);
        }
      } else {
        setError("Código inválido ou expirado.");
      }
    } finally {
      setLoading(false);
    }
  };

  // =======================================================
  // 🖼️ TELA 1 — USERNAME + SENHA
  // =======================================================
  if (step === "login") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
        <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
          <CardContent className="p-6 space-y-6">
            <h1 className="text-3xl font-semibold text-center text-gray-800">🔐 Login</h1>

            <div className="space-y-3">
              <Input 
                placeholder="Usuário" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
              />
              <Input 
                placeholder="Senha" 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
              />
            </div>

            {error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-red-600 text-sm text-center">{error}</p>
              </div>
            )}

            <Button 
              onClick={handleLoginStep1} 
              disabled={loading || !username || !password}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium"
            >
              {loading ? "Entrando..." : "Entrar"}
            </Button>

            <div className="text-center text-sm">
              <Link className="text-blue-600 hover:underline" href="/signup">
                Criar conta
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // =======================================================
  // 🖼️ TELA 2 — DIGITAR CÓDIGO 2FA
  // =======================================================
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          <h1 className="text-3xl font-semibold text-center text-gray-800">🔑 Verifique seu Código</h1>

          <p className="text-center text-gray-600 text-sm">
            Enviamos um código de 6 dígitos para seu e-mail.
          </p>

          <Input
            placeholder="Código 2FA"
            value={twoFACode}
            onChange={(e) => setTwoFACode(e.target.value)}
            className="text-center text-lg tracking-widest"
            maxLength={6}
          />

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-600 text-sm text-center">{error}</p>
            </div>
          )}

          <Button 
            onClick={handleLoginStep2} 
            disabled={loading || twoFACode.length !== 6}
            className="w-full bg-green-600 hover:bg-green-700 text-white font-medium"
          >
            {loading ? "Verificando..." : "Confirmar código"}
          </Button>

          <Button
            variant="outline"
            onClick={() => {
              setStep("login");
              setError(null);
            }}
            className="w-full text-gray-700 border-gray-400 hover:bg-gray-100"
          >
            Voltar
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}