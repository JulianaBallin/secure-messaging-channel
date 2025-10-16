"use client";

import { useState } from "react";
import Link from "next/link";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function SignupPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSignup = () => {
    console.log("Signup:", { username, password });
    // Chamar backend para cadastro
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          <h1 className="text-3xl font-semibold text-center text-gray-800">📝 Cadastro</h1>

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

          <Button
            onClick={handleSignup}
            className="w-full mt-2 bg-green-600 hover:bg-green-700 text-white font-medium"
          >
            Cadastrar
          </Button>

          <div className="flex justify-between items-center pt-2 text-sm">
            <Link href="/login" className="text-green-700 hover:underline">
              Já tem conta?
            </Link>
            <Link href="/chat" className="text-green-700 hover:underline">
              Ir para o Chat
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
