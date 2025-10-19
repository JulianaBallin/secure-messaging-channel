"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import Link from "next/link";
import { fetchJSON } from "@/lib/utils";

export default function SignupPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const router = useRouter();

  const handleSignup = async () => {
    setError(null);
    setOk(null);
    setLoading(true);
    try {
      const data = await fetchJSON("/api/register", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setOk("Conta criada! Faça login.");
      setTimeout(()=> router.push("/login"), 800);
    } catch (e:any) {
      setError(e.message || "Falha no cadastro");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          <h1 className="text-3xl font-semibold text-center text-gray-800">📝 Criar Conta</h1>
          <div className="space-y-3">
            <Input placeholder="Usuário" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="Senha" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && <p className="text-red-600 text-sm text-center">{error}</p>}
          {ok && <p className="text-green-700 text-sm text-center">{ok}</p>}
          <Button onClick={handleSignup} disabled={loading} className="w-full bg-green-600 hover:bg-green-700 text-white font-medium">
            {loading ? "Criando..." : "Criar conta"}
          </Button>
          <div className="text-center text-sm">
            <Link className="text-blue-600 hover:underline" href="/login">Já tenho conta</Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
