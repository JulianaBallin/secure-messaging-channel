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
  const [contacts, setContacts] = useState<string[]>([]);
  const [text, setText] = useState("");
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [groupMessages, setGroupMessages] = useState<GroupMessage[]>([]);
  const [newGroup, setNewGroup] = useState("");
  const [newMember, setNewMember] = useState("");
  const [loading, setLoading] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [unreadMap, setUnreadMap] = useState<Record<string, number>>({});
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
  const loadInboxFor = async (contactName: string) => {
    if (!user || !contactName) return;
    try {
      const data = await fetchJSON(`/api/messages/inbox/${user}/${contactName}`);
      setMessages(data.messages || []);
      scrollToBottom();
    } catch (e) {
      console.error("Erro ao carregar mensagens privadas:", e);
    }
  };

  const loadUnread = async () => {
    if (!user) return;
    try {
      const data = await fetchJSON(`/api/unread/${user}`);
      const map: Record<string, number> = {};
      (data.unread || []).forEach((u: any) => {
        map[u.contact] = u.unread_count;
      });
      setUnreadMap(map);
    } catch (e) {
      console.error("Erro ao carregar unread:", e);
    }
  };

  const scrollToBottom = () => {
    // Evita rolagem forçada em loop
    requestAnimationFrame(() =>
      bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" })
    );
  };

  // Atualiza apenas quando há um contato selecionado
  useEffect(() => {
    if (mode !== "private" || !user || !receiver) return;
    loadInboxFor(receiver); // chama a versão que recebe o contato
    const id = setInterval(() => loadInboxFor(receiver), 2000); // menor delay, mas controlado
    return () => clearInterval(id);
  }, [user, mode, receiver]);

  useEffect(() => {
    if (!user) return;
    loadUnread();
    const id = setInterval(loadUnread, 2000);
    return () => clearInterval(id);
  }, [user]);

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
            <div className="flex h-96 bg-white border rounded-xl overflow-hidden">
              {/* 🧭 LISTA DE CONTATOS */}
              <div className="w-[14rem] shrink-0 border-r bg-gray-50 flex flex-col">
                <div className="p-2 flex justify-between items-center border-b">
                  <span className="font-semibold text-gray-700">Contatos</span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={async () => {
                      const data = await fetchJSON(`/api/users/all`);
                      // filtra o próprio usuário
                      const filtered = data.users.filter((u: string) => u !== user);
                      setContacts(filtered);
                    }}
                  >
                    🔄 Atualizar
                  </Button>
                </div>
                <div className="flex-1 overflow-y-auto">
                  {contacts.length === 0 ? (
                    <p className="text-sm text-gray-500 text-center mt-4">
                      Nenhum contato carregado.
                    </p>
                  ) : (
                    contacts.map((c) => (
                      <button
                        key={c}
                        onClick={() => {
                          setReceiver(c);
                          loadInboxFor(c);
                          loadUnread(); // limpa o unread após abrir o chat
                        }}
                        className={`w-full text-left px-3 py-2 flex justify-between items-center hover:bg-gray-200 ${
                          receiver === c ? "bg-blue-100 font-semibold" : ""
                        }`}
                      >
                        <span>{c}</span>

                        {unreadMap[c] > 0 && (
                          <span className="text-xs bg-blue-500 text-white px-2 py-0.5 rounded-full">
                            {unreadMap[c]}
                          </span>
                        )}
                      </button>
                    ))
                  )}
                </div>
              </div>

              {/* 💬 ÁREA DE MENSAGENS */}
              <div className="flex-1 flex flex-col">
                {receiver ? (
                  <>
                    <div className="p-3 border-b flex justify-between items-center bg-gray-50">
                      <h2 className="font-semibold text-gray-700">💬 {receiver}</h2>
                      <Button size="sm" variant="outline" onClick={() => loadInboxFor(receiver)}>
                        🔄
                      </Button>
                    </div>

                    <div className="flex-1 overflow-y-auto p-4 space-y-3">
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

                    {/* INPUT */}
                    <div className="p-2 border-t flex gap-2 bg-gray-50">
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
                ) : (
                  <div className="flex-1 flex items-center justify-center text-gray-400">
                    👈 Escolha um contato para conversar
                  </div>
                )}
              </div>
            </div>
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
                    {!groups.some(g => g.name === selectedGroup) && " (histórico)"}
                  </h2>

                  {groups.some(g => g.name === selectedGroup) && (
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
                  )}
                  
                  {/* Só mostra ferramentas de admin se AINDA está no grupo */}
                  {isAdmin && groups.some(g => g.name === selectedGroup) && (
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
                    </div>
                  )}

                  {/* Só mostra botão de sair se AINDA está no grupo */}
                  {groups.some(g => g.name === selectedGroup) && (
                    <div className="mt-2">
                      <Button
                        onClick={async () => {
                          if (!selectedGroup || !token) return;
                          const confirmLeave = confirm(
                            "Tem certeza que deseja sair do grupo? Se for o admin, o cargo será transferido automaticamente."
                          );
                          if (!confirmLeave) return;

                          try {
                            const res = await fetchJSON(`/api/groups/leave`, {
                              method: "POST",
                              body: JSON.stringify({ token, group: selectedGroup }),
                            });
                            alert(res.message || "👋 Você saiu do grupo.");
                            loadGroups();
                            setSelectedGroup(null);
                          } catch (e) {
                            console.error(e);
                            alert("❌ Erro ao sair do grupo.");
                          }
                        }}
                        variant="outline"
                        className="text-red-600 border-red-600"
                      >
                        🚪 Sair do grupo
                      </Button>
                    </div>
                  )}

                  {/* 🔥 MENSAGENS DO GRUPO – sempre aparecem, mesmo se saiu */}
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

                  {/* 🔥 INPUT – só aparece se ainda for membro */}
                  {groups.some(g => g.name === selectedGroup) && (
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
                  )}
                </>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
