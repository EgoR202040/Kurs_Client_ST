#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <sys/socket.h>
#include <boost/program_options.hpp>
#include <string>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <memory>

#define buff_size 4096
std::string client_ID = "000001";

bool reg_user(int sock, std::string user_login, std::string user_pass) {
    try {
        std::unique_ptr<char[]> buff(new char[buff_size]);
        std::string data = user_login + ':' + user_pass;
        
        // Отправка данных регистрации
        if (send(sock, data.c_str(), data.length(), 0) <= 0) {
            throw std::runtime_error("Ошибка отправки данных регистрации");
        }

        // Получение ответа от сервера
        int rc = recv(sock, buff.get(), 2, 0);
        if (rc != 2 || std::string(buff.get(), 2) != "OK") {
            throw std::runtime_error("Ошибка регистрации на сервере");
        }

        std::cout << "Регистрация прошла успешно" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка регистрации: " << e.what() << std::endl;
        return false;
    }
}

bool send_file(int sock, std::string filepath) {
    try {
        std::unique_ptr<char[]> buff(new char[buff_size]);
        
        // Открытие файла
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Не удалось открыть файл: " + filepath);
        }

        // Получение размера файла
        size_t file_size = file.tellg();
        file.seekg(0);

        // Извлечение имени файла
        size_t last_slash = filepath.find_last_of("/\\");
        std::string filename = (last_slash == std::string::npos) 
                            ? filepath 
                            : filepath.substr(last_slash + 1);

        // 1. Отправка имени файла
        if (send(sock, filename.c_str(), filename.length(), 0) <= 0) {
            throw std::runtime_error("Ошибка отправки имени файла");
        }

        // Получение подтверждения
        int rc = recv(sock, buff.get(), 2, 0);
        if (rc != 2 || std::string(buff.get(), 2) != "OK") {
            throw std::runtime_error("Сервер не подтвердил получение имени файла");
        }

        // 2. Отправка размера файла (как binary)
        if (send(sock, &file_size, sizeof(file_size), 0) <= 0) {
            throw std::runtime_error("Ошибка отправки размера файла");
        }

        // Получение подтверждения
        rc = recv(sock, buff.get(), 2, 0);
        if (rc != 2 || std::string(buff.get(), 2) != "OK") {
            throw std::runtime_error("Сервер не подтвердил получение размера файла");
        }

        // 3. Отправка содержимого файла
        size_t remaining = file_size;
        while (remaining > 0) {
            size_t chunk_size = std::min(remaining, static_cast<size_t>(buff_size));
            file.read(buff.get(), chunk_size);
            
            if (send(sock, buff.get(), chunk_size, 0) <= 0) {
                throw std::runtime_error("Ошибка отправки содержимого файла");
            }
            
            remaining -= chunk_size;
        }

        file.close();
        std::cout << "Файл успешно отправлен" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка отправки файла: " << e.what() << std::endl;
        return false;
    }
}

std::string md5(std::string input_str) {
    using namespace CryptoPP;
    Weak::MD5 hash;
    std::string new_hash;
    StringSource(input_str, true,
                 new HashFilter(hash, new HexEncoder(new StringSink(new_hash))));
    return new_hash;
}

namespace po = boost::program_options;

int main(int argc, char** argv) {
    bool reg = false;
    bool send = false;
    int PORT = 33333;
    const char* SERVER_IP = "127.0.0.1";

    // Настройка опций командной строки (без изменений)
    po::options_description opts("Allowed options");
    opts.add_options()
    ("help,h", "Show help")
    ("port,p", po::value<int>(&PORT)->default_value(33333), "option is int(port for client)")
    ("reg,r", po::bool_switch(&reg), "option is bool(mode for register user)")
    ("send,s", po::bool_switch(&send), "option is bool(mode for send file)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, opts), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    if (vm.count("help")) {
        std::cout << opts << "\n";
        return 0;
    }

    if(reg == false && send == false){
        std::cerr << "Необходимо выбрать 1 из параметров send,reg" << std::endl;
        return 1;
    }
    if (reg && send) {
        std::cerr << "Необходимо выбрать 1 из параметров send,reg" << std::endl;
        return 1;
    }

    // Создание сокета
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        std::cerr << "Error: Could not create socket\n";
        return 1;
    }

    // Настройка адреса сервера
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr) <= 0) {
        std::cerr << "Error: Invalid address or address not supported\n";
        close(clientSocket);
        return 1;
    }

    // Подключение к серверу
    if (connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress)) < 0) {
        std::cerr << "Error: Connection failed\n";
        close(clientSocket);
        return 1;
    }

    std::cout << "Connected to the server at " << SERVER_IP << ":" << PORT << "\n";
    
    // Получение user_ID от пользователя
    std::string user_ID;
    std::cout << "Введите пользовательский идентификатор для подключения к серверу:" << std::endl;
    std::cin >> user_ID;

    // Формирование и отправка начального сообщения
    std::string message = (reg ? "2" : "1") + client_ID + user_ID;
    if (::send(clientSocket, message.c_str(), message.length(), 0) < 0) {
        std::cerr << "Error: Failed to send data\n";
        close(clientSocket);
        return 1;
    }

    // Получение соли от сервера
    std::unique_ptr<char[]> buffer(new char[buff_size]);
    ssize_t bytesReceived = recv(clientSocket, buffer.get(), 16, 0);
    if (bytesReceived != 16) {
        std::cerr << "Error: Failed to receive salt\n";
        close(clientSocket);
        return 1;
    }

    std::string salt(buffer.get(), 16);
    
    // Получение пароля от пользователя
    std::string pass;
    std::cout << "Введите пароль:";
    std::cin >> pass;
    
    // Вычисление и отправка хеша
    std::string password_hash = md5(salt + pass);
    if (::send(clientSocket, password_hash.c_str(), 32, 0) <= 0) {
        std::cerr << "Error: Failed to send password hash\n";
        close(clientSocket);
        return 1;
    }

    // Получение подтверждения аутентификации
    bytesReceived = recv(clientSocket, buffer.get(), buff_size, 0); 
    if (bytesReceived <= 0) {
        std::cerr << "Error: Authentication failed\n";
        close(clientSocket);
        return 1;
    }

    std::string auth_response(buffer.get(), bytesReceived);
    if (auth_response != "OK") {
        std::cerr << "Privileges error: " << auth_response << std::endl;
        close(clientSocket);
        return 1;
    }

    // Выполнение основной операции
    if (send) {
        std::string filepath;
        std::cout << "Введите путь к файлу для отправки: ";
        std::cin >> filepath;
        if (!send_file(clientSocket, filepath)) {
            close(clientSocket);
            return 1;
        }
    } else {
        std::string login, pass;
        std::cout << "Введите логин: ";
        std::cin >> login;
        std::cout << "Введите пароль: ";
        std::cin >> pass;
        if (!reg_user(clientSocket, login, pass)) {
            close(clientSocket);
            return 1;
        }
    }

    // Закрытие соединения
    close(clientSocket);
    std::cout << "Connection closed\n";

    return 0;
}