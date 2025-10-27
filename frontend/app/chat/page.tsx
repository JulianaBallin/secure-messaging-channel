"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { fetchJSON } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

interface MessageItem {
  id: number;
  sender: string;
  receiver: string;
  content: string;
  timestamp?: string;
  outgoing?: boolean;
}

interface Group {
  id: number;
  name: string;
  is_admin?: boolean;
}

interface GroupMessage {
  id: number;
  from: string;
  content: string;
  timestamp: string;
}

export default function ChatPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"private" | "group">("private");
  const [user, setUser] = useState<string | null>(null);
  const [receiver, setReceiver] = useState("");
  const [text, setText] = useState("");
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [groupMessages, setGroupMessages] = useState<GroupMessage[]>([]);
  const [newGroup, setNewGroup] = useState("");
  const [newMember, setNewMember] = useState("");
  const [loading, setLoading] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;

  // 🔐 login check
  useEffect(() => {
    const u = localStorage.getItem("username");
    if (!u) router.push("/login");
    else setUser(u);
  }, [router]);

  // =======================================================
  // 💌 CHAT PRIVADO
  // =======================================================
  const loadInbox = async () => {
    if (!user || !receiver) return;
    try {
      const data = await fetchJSON(`/api/messages/inbox/${user}/${receiver}`);
      setMessages(data.messages || []);
      scrollToBottom();
    } catch (e) {
      console.error("Erro ao carregar mensagens privadas:", e);
    }
  };

  const scrollToBottom = () =>
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: "smooth" }), 100);

  useEffect(() => {
    if (mode !== "private" || !user) return;
    loadInbox();
    const id = setInterval(loadInbox, 4000);
    return () => clearInterval(id);
  }, [user, mode]);

  const sendPrivate = async () => {
    if (!user || !receiver || !text.trim()) {
      alert("⚠️ Digite a mensagem e o destinatário.");
      return;
    }
    setLoading(true);
    try {
      await fetchJSON(`/api/messages/send`, {
        method: "POST",
        body: JSON.stringify({
          token: localStorage.getItem("token"),
          to: receiver,
          content: text,
        }),
      });

      // espelha localmente (mirroring)
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
          sender: user,
          receiver,
          content: text,
          outgoing: true,
          timestamp: new Date().toISOString(),
        },
      ]);

      setText("");
      scrollToBottom();
    } catch (e) {
      alert("❌ Falha ao enviar mensagem privada.");
    } finally {
      setLoading(false);
    }
  };

  // =======================================================
  // 👥 CHAT DE GRUPO
  // =======================================================
  const loadGroups = async () => {
    if (!token) return;
    try {
      const data = await fetchJSON(`/api/groups/my?token=${token}`);
      setGroups(data.groups || []);
    } catch (e) {
      console.error("Erro ao carregar grupos:", e);
    }
  };

  const loadGroupMessages = async (groupName: string) => {
    if (!token) return;
    try {
      const data = await fetchJSON(`/api/groups/${groupName}/messages?token=${token}`);
      setGroupMessages(data.messages || []);
      scrollToBottom();
    } catch (e) {
      console.error("Erro ao carregar mensagens do grupo:", e);
    }
  };

  useEffect(() => {
    if (mode !== "group" || !selectedGroup) return;
    loadGroupMessages(selectedGroup);
    const id = setInterval(() => loadGroupMessages(selectedGroup), 4000);
    return () => clearInterval(id);
  }, [selectedGroup, mode]);

  const sendGroupMessage = async () => {
    if (!selectedGroup || !text.trim() || !token || !user) return;
    setLoading(true);
    try {
      await fetchJSON(`/api/groups/send`, {
        method: "POST",
        body: JSON.stringify({
          token,
          group: selectedGroup,
          content: text,
        }),
      });

      // eco local
      setGroupMessages((prev) => [
        ...prev,
        {
          id: Date.now(),
          from: user,
          content: text,
          timestamp: new Date().toISOString(),
        },
      ]);

      setText("");
      scrollToBottom();
    } catch (e) {
      alert("❌ Falha ao enviar mensagem no grupo.");
    } finally {
      setLoading(false);
    }
  };

  const createGroup = async () => {
    if (!newGroup.trim() || !token) return;
    try {
      await fetchJSON(`/api/groups/create`, {
        method: "POST",
        body: JSON.stringify({ token, name: newGroup }),
      });
      setNewGroup("");
      loadGroups();
    } catch {
      alert("❌ Erro ao criar grupo.");
    }
  };

  const addMember = async () => {
    if (!selectedGroup || !newMember.trim() || !token) return;
    try {
      await fetchJSON(`/api/groups/add_member`, {
        method: "POST",
        body: JSON.stringify({
          token,
          group: selectedGroup,
          username: newMember,
        }),
      });
      setNewMember("");
      alert("✅ Membro adicionado com sucesso!");
    } catch {
      alert("❌ Erro ao adicionar membro.");
    }
  };

  // 🔽 Remove membro
  const removeMember = async () => {
    if (!selectedGroup || !newMember.trim() || !token) return;
    try {
      await fetchJSON(`/api/groups/remove_member`, {
        method: "POST",
        body: JSON.stringify({
          token,
          group: selectedGroup,
          username: newMember,
        }),
      });
      setNewMember("");
      alert("✅ Membro removido com sucesso!");
    } catch (e) {
      console.error(e);
      alert("❌ Erro ao remover membro.");
    }
  };

  // 🔑 Regenera chave
  const regenerateKey = async () => {
    if (!selectedGroup || !token) return;
    try {
      await fetchJSON(`/api/groups/regenerate_key`, {
        method: "POST",
        body: JSON.stringify({ token, group: selectedGroup }),
      });
      alert("🔑 Chave do grupo regenerada com sucesso!");
    } catch (e) {
      console.error(e);
      alert("❌ Erro ao regenerar chave do grupo.");
    }
  };

  // =======================================================
  // UI
  // =======================================================
  if (!user) return null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-100 to-gray-200">
      <Card className="w-full max-w-3xl shadow-lg border border-gray-200 rounded-2xl">
        <CardContent className="p-6 space-y-6">
          {/* HEADER */}
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-semibold text-gray-800">
              {mode === "private" ? "💬 Chat Privado" : "👥 Chat em Grupo"}
            </h1>
            <div className="text-sm text-gray-600">
              🔒 Logado como: <span className="font-semibold">{user}</span>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => setMode("private")}
                variant={mode === "private" ? "default" : "outline"}
              >
                💬 Privado
              </Button>
              <Button
                onClick={() => {
                  setMode("group");
                  loadGroups();
                }}
                variant={mode === "group" ? "default" : "outline"}
              >
                👥 Grupos
              </Button>
              <Button
                className="text-red-600 border-red-600 hover:bg-red-50"
                variant="outline"
                onClick={() => {
                  localStorage.clear();
                  router.push("/login");
                }}
              >
                Sair
              </Button>
            </div>
          </div>

          {/* PRIVADO */}
          {mode === "private" && (
            <>
            <div className="flex gap-2">
              <Button onClick={async () => {
                const data = await fetchJSON(`/api/users/all`);
                alert("Usuários cadastrados:\n" + data.users.join(", "));
              }} variant="outline">
                👥 Ver Contatos
              </Button>
            </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Destinatário"
                  value={receiver}
                  onChange={(e) => setReceiver(e.target.value)}
                />
                <Button onClick={loadInbox} variant="outline">
                  Atualizar
                </Button>
              </div>

              <div className="h-80 overflow-y-auto bg-white border rounded-xl p-4 space-y-3">
                {messages.length === 0 && (
                  <p className="text-sm text-gray-500 text-center">
                    Nenhuma mensagem ainda 👇
                  </p>
                )}
                <AnimatePresence>
                  {messages.map((m, i) => (
                    <motion.div
                      key={m.id ?? i}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className={`flex ${
                        m.sender === user ? "justify-end" : "justify-start"
                      }`}
                    >
                      <div
                        className={`rounded-xl px-3 py-2 max-w-[80%] ${
                          m.sender === user
                            ? "bg-blue-600 text-white"
                            : "bg-gray-100 text-gray-800"
                        }`}
                      >
                        <div className="text-xs opacity-70 mb-1">{m.sender}</div>
                        <div>{m.content}</div>
                        <div className="text-[10px] opacity-60 mt-1 text-right">
                          {new Date(m.timestamp || "").toLocaleTimeString()} ✅
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
                <div ref={bottomRef} />
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Digite sua mensagem..."
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendPrivate()}
                />
                <Button
                  onClick={sendPrivate}
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                >
                  {loading ? "Enviando..." : "Enviar"}
                </Button>
              </div>
            </>
          )}

          {/* GRUPOS */}
          {mode === "group" && (
            <>
              <div className="flex gap-2">
                <Input
                  placeholder="Novo grupo"
                  value={newGroup}
                  onChange={(e) => setNewGroup(e.target.value)}
                />
                <Button onClick={createGroup} className="bg-green-600 text-white">
                  Criar
                </Button>
                <Button onClick={loadGroups} variant="outline">
                  🔄 Atualizar
                </Button>
              </div>

              <div className="flex gap-2 overflow-x-auto">
                {groups.map((g) => (
                  <Button
                    key={g.id}
                    onClick={() => {
                      setSelectedGroup(g.name);
                      setIsAdmin(g.is_admin || false);
                      loadGroupMessages(g.name);
                    }}
                    variant={selectedGroup === g.name ? "default" : "outline"}
                  >
                    {g.name}
                  </Button>
                ))}
              </div>

              {selectedGroup && (
                <>
                  <h2 className="text-lg font-semibold text-gray-700">
                    💬 Grupo: {selectedGroup}
                  </h2>

                  <Button
                    onClick={async () => {
                      const data = await fetchJSON(`/api/groups/${selectedGroup}/members?token=${token}`);
                      alert(
                        `👑 Admin: ${data.admin}\n\n👥 Membros:\n${data.members.join("\n")}`
                      );
                    }}
                    variant="outline"
                  >
                    📋 Ver Membros
                  </Button>
                  
                  {isAdmin && (
                    <div className="flex flex-wrap gap-2 mb-2">
                      <Input
                        placeholder="Gerenciar membro..."
                        value={newMember}
                        onChange={(e) => setNewMember(e.target.value)}
                        className="flex-1"
                      />
                      <Button onClick={addMember} variant="outline">
                        ➕ Adicionar
                      </Button>
                      <Button
                        onClick={removeMember}
                        variant="outline"
                        className="text-red-600 border-red-600"
                      >
                        ❌ Remover
                      </Button>
                      <Button
                        onClick={regenerateKey}
                        className="bg-yellow-500 hover:bg-yellow-600 text-white"
                      >
                        🔑 Regenerar Chave
                      </Button>
                    </div>
                  )}

                  <div className="h-80 overflow-y-auto bg-white border rounded-xl p-4 space-y-3">
                    {groupMessages.length === 0 && (
                      <p className="text-sm text-gray-500 text-center">
                        Sem mensagens ainda 👇
                      </p>
                    )}
                    <AnimatePresence>
                      {groupMessages.map((m, i) => (
                        <motion.div
                          key={m.id ?? i}
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -10 }}
                          className={`flex ${
                            m.from === user ? "justify-end" : "justify-start"
                          }`}
                        >
                          <div
                            className={`rounded-xl px-3 py-2 max-w-[80%] ${
                              m.from === user
                                ? "bg-blue-600 text-white"
                                : "bg-gray-100 text-gray-800"
                            }`}
                          >
                            <div className="text-xs font-semibold mb-1">
                              {m.from === user ? "Você" : m.from}
                            </div>
                            <div>{m.content}</div>
                            <div className="text-[10px] opacity-60 mt-1 text-right">
                              {new Date(m.timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        </motion.div>
                      ))}
                    </AnimatePresence>
                    <div ref={bottomRef} />
                  </div>

                  <div className="flex gap-2">
                    <Input
                      placeholder="Digite uma mensagem..."
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && sendGroupMessage()}
                    />
                    <Button
                      onClick={sendGroupMessage}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-700 text-white"
                    >
                      {loading ? "Enviando..." : "Enviar"}
                    </Button>
                  </div>
                </>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
