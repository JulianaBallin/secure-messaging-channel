"use client";

import { useState, useEffect, useRef } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import Link from "next/link";
import { useRouter } from "next/navigation";

interface ChatMessage {
  sender: string;
  text: string;
  self?: boolean;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [msg, setMsg] = useState("");
  const ws = useRef<WebSocket | null>(null);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }

    const socket = new WebSocket("ws://127.0.0.1:8000/ws");
    ws.current = socket;

    socket.onopen = () => {
      socket.send(JSON.stringify({ action: "resume_session", token }));
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.message) {
          setMessages((prev) => [
            ...prev,
            { sender: "Outro usuário", text: data.message },
          ]);
        }
      } catch {
        setMessages((prev) => [
          ...prev,
          { sender: "Sistema", text: event.data },
        ]);
      }
    };

    socket.onerror = (err) => console.error("WebSocket erro:", err);

    return () => socket.close();
  }, [router]);

  const sendMessage = () => {
    if (!msg.trim() || !ws.current) return;

    ws.current.send(JSON.stringify({ action: "send_message", content: msg }));

    setMessages((prev) => [...prev, { sender: "Você", text: msg, self: true }]);
    setMsg("");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 flex flex-col gap-4">
          <h1 className="text-3xl font-semibold text-center text-gray-800">
            💬 Chat em Grupo
          </h1>

          {/* Área de mensagens */}
          <div className="h-72 overflow-y-auto border rounded-md bg-gray-50 p-3 space-y-2 text-gray-700">
            {messages.length === 0 ? (
              <p className="text-center text-gray-400">
                Nenhuma mensagem ainda
              </p>
            ) : (
              messages.map((m, i) => (
                <div
                  key={i}
                  className={`flex ${
                    m.self ? "justify-end" : "justify-start"
                  }`}
                >
                  <div
                    className={`px-3 py-2 rounded-xl text-sm max-w-[75%] shadow-sm ${
                      m.self
                        ? "bg-blue-600 text-white"
                        : "bg-gray-200 text-gray-800"
                    }`}
                  >
                    {!m.self && (
                      <span className="block text-xs text-gray-600 mb-1">
                        {m.sender}
                      </span>
                    )}
                    {m.text}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Campo de envio */}
          <div className="flex gap-2">
            <Input
              placeholder="Digite sua mensagem..."
              value={msg}
              onChange={(e) => setMsg(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && sendMessage()}
            />
            <Button
              onClick={sendMessage}
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium"
            >
              Enviar
            </Button>
          </div>

          {/* Links extras */}
          <div className="flex justify-between items-center pt-2 text-sm">
            <Link href="/login" className="text-blue-600 hover:underline">
              Login
            </Link>
            <Link href="/signup" className="text-blue-600 hover:underline">
              Signup
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
