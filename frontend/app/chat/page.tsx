"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function ChatPage() {
  const [messages, setMessages] = useState<string[]>([]);
  const [msg, setMsg] = useState("");
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    ws.current = new WebSocket("ws://127.0.0.1:8000/ws");
    ws.current.onmessage = (event) => setMessages((prev) => [...prev, event.data]);
    return () => ws.current?.close();
  }, []);

  const sendMessage = () => {
    if (!msg.trim() || !ws.current) return;
    ws.current.send(msg);
    setMessages((prev) => [...prev, `Você: ${msg}`]);
    setMsg("");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-md shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 flex flex-col gap-4">
          <h1 className="text-3xl font-semibold text-center text-gray-800">💬 Chat</h1>

          <div className="h-72 overflow-y-auto border rounded-md bg-gray-50 p-3 space-y-2 text-gray-700">
            {messages.length === 0 ? (
              <p className="text-center text-gray-400">Nenhuma mensagem ainda</p>
            ) : (
              messages.map((m, i) => <div key={i}>{m}</div>)
            )}
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Digite sua mensagem..."
              value={msg}
              onChange={(e) => setMsg(e.target.value)}
            />
            <Button
              onClick={sendMessage}
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium"
            >
              Enviar
            </Button>
          </div>

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
