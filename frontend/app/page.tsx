"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function HomePage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-8 flex flex-col items-center text-center space-y-6">
          <h1 className="text-4xl font-bold text-gray-800">CipherTalk 💬</h1>
          <p className="text-gray-600 text-sm">
            Um canal de mensagens seguro com criptografia ponta a ponta.
          </p>

          <div className="flex flex-col gap-3 w-full">
            <Link href="/login" className="w-full">
              <Button className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium">
                🔐 Login
              </Button>
            </Link>

            <Link href="/signup" className="w-full">
              <Button className="w-full bg-green-600 hover:bg-green-700 text-white font-medium">
                📝 Criar Conta
              </Button>
            </Link>

          </div>
        </CardContent>
      </Card>
    </div>
  );
}


