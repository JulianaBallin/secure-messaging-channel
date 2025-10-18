"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { fetchJSON } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

interface MessageItem {
  sender: string;
  receiver: string;
  content: string;
  timestamp?: string;
  mirror?: boolean;
}

export default function ChatPage() {
  const router = useRouter();
  const [user, setUser] = useState<string | null>(null);
  const [receiver, setReceiver] = useState("");
  const [text, setText] = useState("");
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  // 🔐 Verifica login
  useEffect(() => {
    const storedUser = localStorage.getItem("username");
    if (storedUser) setUser(storedUser);
    else router.push("/login");
  }, [router]);

  // 📩 Carrega mensagens do backend
  const loadInbox = async () => {
    if (!user) return;
    try {
      const data = await fetchJSON(`/api/messages/inbox/${user}`);
      const fetched = data.messages || data;

      // Mantém mensagens já enviadas localmente (mirror)
      setMessages((prev) => {
        const merged = [...prev];
        for (const msg of fetched) {
          // evita duplicatas
          if (
            !merged.some(
              (m) =>
                m.sender === msg.sender &&
                m.receiver === msg.receiver &&
                m.content === msg.content &&
                m.timestamp === msg.timestamp
            )
          ) {
            merged.push(msg);
          }
        }
        return merged;
      });

      setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch (e) {
      console.error("Erro ao carregar mensagens:", e);
    }
  };

  useEffect(() => {
    if (!user) return;
    loadInbox();
    const id = setInterval(loadInbox, 4000);
    return () => clearInterval(id);
  }, [user]);

  // ✉️ Envio com persistência local
  const sendMessage = async () => {
    if (!user || !receiver || !text.trim()) {
      alert("⚠️ Digite uma mensagem e informe o destinatário.");
      return;
    }

    const newMsg: MessageItem = {
      sender: user,
      receiver,
      content: text,
      timestamp: new Date().toISOString(),
      mirror: true,
    };

    // exibe e salva localmente
    setMessages((prev) => [...prev, newMsg]);
    setText("");
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: "smooth" }), 100);

    setLoading(true);
    try {
      await fetchJSON(`/api/messages/send`, {
        method: "POST",
        body: JSON.stringify({
          token: localStorage.getItem("token"),
          to: receiver,
          content: newMsg.content,
        }),
      });
      console.log(`[SEND_OK] ${user} → ${receiver}`);
    } catch (e) {
      console.error("Erro ao enviar:", e);
      alert("❌ Falha ao enviar mensagem.");
    } finally {
      setLoading(false);
    }
  };

  // 🚪 Logout
  const logout = () => {
    localStorage.clear();
    router.push("/login");
  };

  if (!user) return null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-2xl shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-semibold text-gray-800">💬 Chat Seguro</h1>
            <div className="flex gap-3 text-sm">
              <span className="text-gray-600">
                Logado como <b>{user}</b>
              </span>
              <button onClick={logout} className="text-red-600 hover:underline">
                Sair
              </button>
            </div>
          </div>

          {/* Destinatário */}
          <div className="flex gap-2">
            <Input
              placeholder="Destinatário"
              value={receiver}
              onChange={(e) => setReceiver(e.target.value)}
            />
            <Button onClick={loadInbox} className="bg-gray-100 text-gray-700 border">
              Atualizar
            </Button>
          </div>

          {/* Caixa de mensagens */}
          <div className="h-80 overflow-y-auto bg-white border rounded-xl p-4 space-y-3">
            {messages.length === 0 && (
              <p className="text-sm text-gray-500">Sem mensagens. Envie uma 👇</p>
            )}

            <AnimatePresence>
              {messages
                .sort(
                  (a, b) =>
                    new Date(a.timestamp || 0).getTime() -
                    new Date(b.timestamp || 0).getTime()
                )
                .map((m, idx) => (
                  <motion.div
                    key={`${m.sender}-${m.timestamp}-${idx}`}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}
                    className={`flex ${m.sender === user ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`rounded-xl px-3 py-2 max-w-[80%] ${
                        m.sender === user
                          ? "bg-blue-600 text-white"
                          : "bg-gray-100 text-gray-800"
                      }`}
                    >
                      <div className="text-xs opacity-70 mb-1">
                        {m.sender} → {m.receiver}
                      </div>
                      <div className="whitespace-pre-wrap break-words">
                        {m.content || "(vazia)"}
                      </div>
                      {m.timestamp && (
                        <div className="text-[10px] opacity-60 mt-1 text-right">
                          {new Date(m.timestamp).toLocaleTimeString()}
                        </div>
                      )}
                    </div>
                  </motion.div>
                ))}
            </AnimatePresence>

            <div ref={bottomRef} />
          </div>

          {/* Campo de envio */}
          <div className="flex gap-2">
            <Input
              placeholder="Digite sua mensagem..."
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && sendMessage()}
            />
            <Button
              onClick={sendMessage}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium"
            >
              {loading ? "Enviando..." : "Enviar"}
            </Button>
          </div>

          {/* Links */}
          <div className="flex justify-between text-sm">
            <Link className="text-blue-600 hover:underline" href="/login">
              Login
            </Link>
            <Link className="text-blue-600 hover:underline" href="/signup">
              Criar Conta
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
