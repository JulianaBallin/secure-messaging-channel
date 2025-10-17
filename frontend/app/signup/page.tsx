"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import Link from "next/link";

export default function SignupPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const router = useRouter();

  const handleSignup = async () => {
    setMessage(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const text = await res.text();
        setMessage({ type: "error", text: "❌ Falha ao cadastrar: " + text });
        return;
      }

      setMessage({ type: "success", text: "✅ Usuário cadastrado com sucesso!" });
      setTimeout(() => router.push("/login"), 1500);
    } catch (err) {
      console.error(err);
      setMessage({ type: "error", text: "❌ Erro de conexão com o servidor." });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          <h1 className="text-3xl font-semibold text-center text-gray-800">📝 Cadastro</h1>

          <div className="space-y-3">
            <Input placeholder="Usuário" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="Senha" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>

          <Button onClick={handleSignup} className="w-full mt-2 bg-green-600 hover:bg-green-700 text-white font-medium">
            Cadastrar
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

          <Link href="/login" className="text-blue-600 hover:underline block text-center mt-2">
            Já possui conta? Login
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
