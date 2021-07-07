import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Server {

    private static String ipAddress;
    private static final String fileStorage = "Z:\\";
    private static int status = 200;
    private static byte[] serverResponse;

    public static void main(String[] args){
        try {
            ipAddress = InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        boolean isWork = true;
        while (isWork){
            try {
                System.out.println("Enter port number:");
                Scanner scan = new Scanner(System.in);

                HttpServer server = HttpServer.create(new InetSocketAddress(scan.nextInt()), 5);

                isWork = false;

                System.out.println(ipAddress + ":" + server.getAddress().getPort());

                server.createContext("/", new Handler());
                server.setExecutor(null);
                server.start();
            }catch (InputMismatchException e){
                System.out.println("Incorrect input use only numbers!");
            }catch (BindException e){
                System.out.println("Port is already in use!");
            }catch (IOException e){
                e.printStackTrace();
            }
        }
    }

    private static class Handler implements HttpHandler {

        public void handle(HttpExchange exchange) throws IOException {

            serverResponse = new byte[0];
            String requestURI = exchange.getRequestURI().toString();
            String filename = requestURI.substring(requestURI.lastIndexOf('/') + 1);

            try {
                switch (exchange.getRequestMethod()) {

                    case "GET" -> get(filename);
                    case "POST" -> post(exchange, filename);
                    case "PUT" -> put(exchange, filename);
                    case "DELETE" -> delete(filename);
                    case "MOVE" -> move(exchange, filename);
                    case "COPY" -> copy(exchange, filename);
                    default -> status = 405;
                }
            }catch (FileNotFoundException | NoSuchFileException e) {
                status = 404;
            } catch (IOException e){
                status = 400;
            }

            exchange.sendResponseHeaders(status, serverResponse.length);
            OutputStream os = exchange.getResponseBody();

            os.write(serverResponse);
            os.close();
        }

        private static void get(String filename) throws  IOException{
            serverResponse = Files.readAllBytes(Paths.get(fileStorage + filename));
        }

        private static void post(HttpExchange exchange, String filename) throws IOException{
            Path path = Paths.get(fileStorage + filename);
            if (!Files.exists(path)){
                Files.createFile(path);
            }
            Files.write(path, getParams(exchange.getRequestBody(), new String[]{"content"})[0].getBytes(), StandardOpenOption.APPEND);//дозапись в конец файла
        }

        private static void put(HttpExchange exchange, String filename) throws IOException{
            Path path = Paths.get(fileStorage + filename);
            if (!Files.exists(path)){
                Files.createFile(path);
            }
            Files.write(path, getParams(exchange.getRequestBody(), new String[]{"content"})[0].getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
        }

        private static void delete(String filename) throws IOException{
            Files.delete(Paths.get(fileStorage + filename));
        }

        private static void move(HttpExchange exchange, String filename) throws IOException{
            Path path = Paths.get(getParams(exchange.getRequestBody(), new String[]{"newPath"})[0] + filename);

            if (Files.exists(path)){
                exchange.getResponseHeaders().put("message", new ArrayList<>(Collections.singletonList("Файл со схожим имененм уже существует")));//установка заголовка ответа
                throw new IOException();
            }

            Files.move(Paths.get(fileStorage + filename), path);
        }

        private static void copy(HttpExchange exchange, String filename) throws IOException{
            String[] params = getParams(exchange.getRequestBody(), new String[]{"newPath", "newFilename"});
            Path path = Paths.get(params[0] + params[1]);

            if (Files.exists(path)){
                exchange.getResponseHeaders().put("message", new ArrayList<>(Collections.singletonList("Файл со схожим имененм уже существует")));
                throw new IOException();
            }

            Files.copy(Paths.get(fileStorage + filename), path);
        }

        private static String[] getParams(InputStream body, String[] params) throws IOException{

            StringBuilder bodyBuilder = new StringBuilder();
            BufferedReader in = new BufferedReader(new InputStreamReader(body));

            String line;

            while ((line = in.readLine()) != null) {
                bodyBuilder.append(URLDecoder.decode(line));
            }

            String[] result = new String[params.length];
            int i = 0;
            int start,end;
            for (String param : params) {
                start = bodyBuilder.indexOf(param + "=") + param.length() + 1;
                if (start > bodyBuilder.lastIndexOf("&")) {
                    result[i++] = bodyBuilder.substring(start);
                } else {
                    end = bodyBuilder.substring(start).indexOf("&");
                    result[i++] = bodyBuilder.substring(start, end + start);
                }
            }

            in.close();
            return result;
        }
    }
}