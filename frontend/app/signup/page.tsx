// frontend/app/signup/page.tsx
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
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const router = useRouter();

  // Função para validar formato de email
  const isValidEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  // Função para validar domínio de email
  const isValidEmailDomain = (email: string): boolean => {
    const domains = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
      'protonmail.com', 'aol.com', 'zoho.com', 'yandex.com', 'mail.com',
      'gmx.com', 'live.com', 'msn.com', 'bol.com.br', 'uol.com.br',
      'terra.com.br', 'ig.com.br', 'r7.com', 'globo.com', 'oi.com.br',
      'zipmail.com.br', 'folha.com.br', 'osite.com.br'
    ];
    
    const domain = email.split('@')[1]?.toLowerCase();
    return domains.some(validDomain => domain === validDomain);
  };

  const handleSignup = async () => {
    setError(null);
    setOk(null);
    
    // Validações antes de enviar
    if (!username || !password || !email) {
      setError("Todos os campos são obrigatórios.");
      return;
    }

    if (username.length < 3) {
      setError("O usuário deve ter pelo menos 3 caracteres.");
      return;
    }

    if (password.length < 6) {
      setError("A senha deve ter pelo menos 6 caracteres.");
      return;
    }

    if (!isValidEmail(email)) {
      setError("Por favor, insira um email válido (exemplo: usuario@provedor.com).");
      return;
    }

    if (!isValidEmailDomain(email)) {
      setError("Domínio de email não reconhecido. Use um provedor de email válido.");
      return;
    }

    setLoading(true);
    
    try {
      // 🔑 1️⃣ Gera o par de chaves localmente (RSA 2048)
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      // 2️⃣ Exporta a pública em formato PEM
      const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pubPem = `-----BEGIN PUBLIC KEY-----\n${btoa(
        String.fromCharCode(...new Uint8Array(spki))
      )}\n-----END PUBLIC KEY-----`;

      // 3️⃣ Exporta a privada e salva localmente (apenas no browser)
      const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      localStorage.setItem(
        `privateKey_${username}`,
        btoa(String.fromCharCode(...new Uint8Array(pkcs8)))
      );

      // 🚀 4️⃣ Envia o cadastro pro backend
      await fetchJSON("/api/register", {
        method: "POST",
        body: JSON.stringify({ 
          username, 
          password, 
          email, 
          public_key: pubPem 
        }),
      });

      setOk("Conta criada com sucesso! Faça login.");
      setTimeout(() => router.push("/login"), 2000);
    } catch (e: unknown) {
      console.error(e);
      const errorMessage = e instanceof Error ? e.message : "Falha no cadastro";
      
      // Tratamento específico de erros do backend
      if (errorMessage.includes("Email inválido")) {
        setError("Email inválido. Use um provedor de email válido como Gmail, Yahoo, Outlook, etc.");
      } else if (errorMessage.includes("Email já cadastrado")) {
        setError("Este email já está cadastrado. Use outro email ou faça login.");
      } else if (errorMessage.includes("Usuário já existe")) {
        setError("Este usuário já existe. Escolha outro nome de usuário.");
      } else if (errorMessage.includes("A senha deve ter")) {
        setError(errorMessage); // Mostra a mensagem específica sobre senha
      } else {
        setError(errorMessage || "Falha no cadastro. Tente novamente.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          <h1 className="text-3xl font-semibold text-center text-gray-800">📝 Criar Conta</h1>
          
          <div className="space-y-4">
            <div>
              <Input 
                placeholder="Usuário (mín. 3 caracteres)" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
              />
            </div>
            
            <div>
              <Input 
                placeholder="Email válido" 
                type="email" 
                value={email} 
                onChange={(e) => setEmail(e.target.value)}
              />
              <p className="text-xs text-gray-500 mt-1">
                Exemplo: usuario@gmail.com
              </p>
            </div>
            
            <div>
              <Input 
                placeholder="Senha (mín. 6 caracteres)" 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
              />
            </div>
          </div>
          
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-600 text-sm text-center">{error}</p>
            </div>
          )}
          
          {ok && (
            <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
              <p className="text-green-700 text-sm text-center">{ok}</p>
            </div>
          )}
          
          <Button 
            onClick={handleSignup} 
            disabled={loading} 
            className="w-full bg-green-600 hover:bg-green-700 text-white font-medium"
          >
            {loading ? "Criando..." : "Criar conta"}
          </Button>
          
          <div className="text-center text-sm">
            <Link className="text-blue-600 hover:underline" href="/login">
              Já tenho conta
            </Link>
          </div>

          <div className="text-xs text-gray-500 text-center">
            <p>📧 Provedores aceitos: Gmail, Yahoo, Outlook, Hotmail, iCloud, etc.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}