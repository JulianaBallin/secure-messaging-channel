"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import Link from "next/link";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const router = useRouter();

  const handleLogin = async () => {
    setMessage(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const text = await res.text();
        setMessage({ type: "error", text: "❌ Login falhou: " + text });
        return;
      }

      const data = await res.json();
      localStorage.setItem("token", data.token);
      setMessage({ type: "success", text: "✅ Login realizado com sucesso!" });
      setTimeout(() => router.push("/chat"), 1000);
    } catch (err) {
      console.error(err);
      setMessage({ type: "error", text: "❌ Erro de conexão com o servidor." });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          <h1 className="text-3xl font-semibold text-center text-gray-800">🔐 Login</h1>

          <div className="space-y-3">
            <Input placeholder="Usuário" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="Senha" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>

          <Button onClick={handleLogin} className="w-full mt-2 bg-blue-600 hover:bg-blue-700 text-white font-medium">
            Entrar
          </Button>

          {message && (
            <p
              className={`text-center mt-2 ${
                message.type === "success" ? "text-green-600" : "text-red-600"
              }`}
            >
              {message.text}
            </p>
          )}

          <Link href="/signup" className="text-blue-600 hover:underline block text-center mt-2">
            Não possui conta? Signup
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}

