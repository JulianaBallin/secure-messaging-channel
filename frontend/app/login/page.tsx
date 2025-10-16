"use client";

import { useState } from "react";
import Link from "next/link";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("");

  const handleLogin = async () => {
    const res = await fetch("http://127.0.0.1:8000/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.success) setStatus("✅ Login bem-sucedido!");
    else setStatus("❌ " + data.error);
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

          <p className="text-center text-sm text-gray-500">{status}</p>

          <div className="flex justify-between items-center pt-2 text-sm">
            <Link href="/signup" className="text-blue-600 hover:underline">Criar conta</Link>
            <Link href="/chat" className="text-blue-600 hover:underline">Ir para o Chat</Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
