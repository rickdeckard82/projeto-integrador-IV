import React from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../auth/AuthContext.jsx";

const LINKS = [
  { to: "/dashboard", label: "Painel" },
  { to: "/comunicados", label: "Comunicados" },
  { to: "/offices", label: "Ofícios" },
  { to: "/domains", label: "Domínios" },
  { to: "/ip-blocks", label: "IPs" },
  { to: "/ip-blocks/preview", label: "CFG IP" },
  { to: "/rpz", label: "RPZ" },
  { to: "/general", label: "Geral" },
  { to: "/log", label: "Log" },
];

// Só para quem tem acesso ao módulo de abuse (dados pessoais).
const ABUSE_LINK = { to: "/abuse", label: "Abuse" };

export default function Nav() {
  const { user } = useAuth();
  const links = user?.abuse_access
    ? [...LINKS.slice(0, -2), ABUSE_LINK, ...LINKS.slice(-2)]
    : LINKS;

  return (
    <nav>
      {links.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          {link.label}
        </NavLink>
      ))}
    </nav>
  );
}
