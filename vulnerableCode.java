import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ATENÇÃO: 
 * ==========================================================
 * ESTE CÓDIGO É INTENCIONALMENTE VULNERÁVEL.
 * 
 * Ele foi criado APENAS para fins educacionais, para que
 * ferramentas de SAST (CodeQL, Codacy, etc.) e de DAST 
 * possam identificar problemas de segurança.
 * 
 * NÃO UTILIZAR NENHUMA DESTAS PRÁTICAS EM CÓDIGO REAL.
 * ==========================================================
 */
public class VulnerableCode {

    // 1) CREDENCIAIS EM CÓDIGO (HARD-CODED CREDENTIALS)
    // Problema: usuário, senha e URL do banco estão expostos no código-fonte.
    // Ferramentas de SAST e de secret scanning costumam apontar isso.
    private static final String DB_URL = "jdbc:mysql://localhost:3306/minha_aplicacao";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "senha_super_secreta";

    /**
     * Simula um processo de login extremamente inseguro.
     *
     * Vulnerabilidades principais:
     * - SQL Injection (concatenação direta de parâmetros na query).
     * - Exposição de credenciais no código.
     * - Uso de Statement em vez de PreparedStatement.
     */
    public boolean loginInseguro(String username, String password) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            // 2) CONEXÃO DIRETA COM CREDENCIAIS HARDCODED
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // 3) SQL INJECTION
            // Problema: username e password entram diretamente na query
            // sem validação ou parametrização.
            String sql = "SELECT * FROM usuarios WHERE username = '" + username
                       + "' AND password = '" + password + "'";

            stmt = conn.createStatement();
            rs = stmt.executeQuery(sql);

            return rs.next(); // se encontrou algum registro, considera login válido

        } catch (Exception e) {
            // 4) TRATAMENTO GENÉRICO DE EXCEÇÃO + PRINT DE STACKTRACE
            // Problema: captura Exception genérica e exibe stack trace,
            // o que pode vazar informações sensíveis em logs.
            e.printStackTrace();
            return false;

        } finally {
            try {
                if (rs != null) rs.close();
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (Exception ignored) {
                // Ignorando exceção de fechamento (também é má prática)
            }
        }
    }

    /**
     * Simula uma busca de usuários por termo de pesquisa.
     *
     * Vulnerabilidade: SQL Injection pela concatenação da string "searchTerm".
     */
    public void buscarUsuarioPorTermo(String searchTerm) {
        Connection conn = null;
        Statement stmt = null;

        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // 5) SQL INJECTION EM CONSULTA DE BUSCA
            String sql = "SELECT * FROM usuarios WHERE nome LIKE '%" + searchTerm + "%'";
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                System.out.println("Usuário encontrado: " + rs.getString("nome"));
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Exemplo de armazenamento de senha com algoritmo fraco.
     *
     * Vulnerabilidade:
     * - Uso de MD5 sem salt, considerado inseguro.
     */
    public String armazenarSenhaInsegura(String senhaPlano) {
        try {
            // 6) USO DE ALGORITMO CRIPTOGRÁFICO FRACO (MD5)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(senhaPlano.getBytes());

            // Converte o array de bytes em string hexadecimal (apenas para exibir)
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }

            String hashInseguro = sb.toString();
            // Em um cenário real, esse hash não deveria ser gerado com MD5
            // e nem sem "salt".
            System.out.println("Senha armazenada (hash inseguro MD5): " + hashInseguro);
            return hashInseguro;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Simula geração de HTML sem sanitização de entrada.
     *
     * Vulnerabilidade:
     * - XSS (Cross-Site Scripting), pois o valor de "nome" é injetado
     *   diretamente na página sem escapar caracteres.
     */
    public String gerarPaginaPerfil(String nome) {
        // 7) XSS – entrada do usuário é colocada diretamente no HTML
        String html =
                "<html>" +
                "<head><title>Perfil do Usuário</title></head>" +
                "<body>" +
                "<h1>Bem-vindo, " + nome + "!</h1>" +
                "<p>Esse é o seu painel.</p>" +
                "</body>" +
                "</html>";

        return html;
    }

    /**
     * Método main apenas para permitir execução simples da classe
     * e facilitar testes básicos.
     *
     * Em um cenário real, essas funcionalidades estariam dentro de um
     * serviço web / controlador HTTP, que seria o alvo de DAST.
     */
    public static void main(String[] args) {
        VulnerableCode app = new VulnerableCode();

        // Exemplo de login inseguro
        System.out.println("Tentando login inseguro...");
        boolean autenticado = app.loginInseguro("admin", "admin123");
        System.out.println("Login realizado? " + autenticado);

        // Exemplo de busca insegura
        System.out.println("\nBuscando usuários com termo inseguro...");
        app.buscarUsuarioPorTermo("teste' OR '1'='1");

        // Exemplo de armazenamento de senha inseguro
        System.out.println("\nArmazenando senha com MD5 (inseguro)...");
        app.armazenarSenhaInsegura("minha_senha_fraca");

        // Exemplo de XSS
        System.out.println("\nGerando HTML de perfil (possível XSS)...");
        String pagina = app.gerarPaginaPerfil("<script>alert('XSS');</script>");
        System.out.println(pagina);
    }
}
