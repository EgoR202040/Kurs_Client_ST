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

bool reg_user(int sock,std::string user_login,std::string user_pass){
    try{
        std::unique_ptr<char[]> buff(new char[buff_size]);
        std::string data = user_login + ':' + user_pass;
        int rc = send(sock,data.c_str(),data.length(),0);
        if(rc<=0){
            throw std::runtime_error("Failed send user_data");
        }
        std::cout << "Данные пользователя отправлены" << std::endl;
        rc = recv(sock,buff.get(),2,0);
        if(rc != 2){
            throw std::runtime_error("Not OK from server");
        }
        std::cout << "Регистрация прошла успешна" << std::endl;
        return true;
    }catch(const std::exception& e){
        std::cout << "Произошла ошибка:";
        std::cout << e.what() << std::endl;
        return false;
    }

}

bool send_file(int sock,std::string filepath) {
    try {
		std::unique_ptr<char[]> buff(new char[buff_size]);
        // Открываем файл для чтения
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + filepath);
        }

        // Получаем размер файла
        int file_size = file.tellg();
        file.seekg(0);

        // Извлекаем имя файла из пути
        size_t last_slash = filepath.find_last_of("/\\");
        std::string filename = (last_slash == std::string::npos) 
                            ? filepath 
                            : filepath.substr(last_slash + 1);

        // Отправляем имя файла
        std::cout << filename << std::endl;
        int rc = send(sock, filename.c_str(), filename.length(), 0);
        if (rc <= 0) {
            file.close();
            throw std::runtime_error("Failed to send filename");
        }
        
		rc = recv(sock,buff.get(),2,0);
		if(rc != 2){
			std::cout << "Not ok received"<<std::endl;
			return 1;
		}
		std::cout << "Имя отправлено" << std::endl;
        // Отправляем размер файла
        rc = send(sock, std::to_string(file_size).c_str(), std::to_string(file_size).length(), 0);
        if (rc <= 0) {
            file.close();
            throw std::runtime_error("Failed to send file size");
        }
		rc = recv(sock,buff.get(),2,0);
		if(rc != 2){
			std::cout << "Not ok received"<<std::endl;
			return 1;
		}
        
        file.read(buff.get(), buff_size);
        rc=send(sock,buff.get(),file_size,0);
        std::cout << "Файл отправлен" <<std::endl;
        file.close();
        return true;
    } catch (const std::exception& e) {
        // Обработка ошибок
        // l1->writelog(e.what());
        return false;
    }
}


std::string md5(std::string input_str)
{
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
    int PORT = 33333; // Port number
    const char* SERVER_IP = "127.0.0.1"; // Server IP address (localhost)

    // Настройка опций командной строки
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
    serverAddress.sin_family = AF_INET; // IPv4
    serverAddress.sin_port = htons(PORT); // Порт
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
	std::string message,user_ID;
	std::cout << "Введите пользовательский идентификатор для подключения к серверу:" <<std::endl;
	std::cin >> user_ID;
    // Отправка данных на сервер
    if(reg){
    	message = "2";
    }else{message="1";}
    message = message + client_ID + user_ID;
    if (::send(clientSocket, message.c_str(), message.length(), 0) < 0) {
        std::cerr << "Error: Failed to send data\n";
        close(clientSocket);
        return 1;
    }

    std::cout << "Message sent to the server: " << message << "\n";

    // Получение данных от сервера
    std::unique_ptr<char[]> buffer(new char[1024]);
    ssize_t bytesReceived = recv(clientSocket, buffer.get(), 16, 0); //16 байт для SALT
    if (bytesReceived != 16) {
        std::cerr << "Error: Failed to salt\n";
        close(clientSocket);
        return 1;
    }

    std::cout << "Received SALT from server: " << buffer.get() << "\n";
	std::string SALT(buffer.get(),16);
	std::string pass;
	std::cout <<"Введите пароль:"<<std::endl;
	std::cin >> pass;
	std::string password_hash = md5(SALT + pass);
	//Отправка SALT серверу
	if (::send(clientSocket, password_hash.c_str(),32, 0) <= 0) {
        std::cerr << "Error: Failed to send SALT\n";
        close(clientSocket);
        return 1;
    }
	bytesReceived = recv(clientSocket, buffer.get(), buff_size, 0); 
    std::string ok(buffer.get(),bytesReceived);
    if(ok != "OK" or ok=="OKOK"){
        std::cerr << ok << std::endl;
    	close(clientSocket);
    	exit(1);
    }
    if(send){
    	std::string filepath;
    	std::cout << "Введите путь к файлу для отправки" << std::endl;
    	std::cin >> filepath;
    	send_file(clientSocket,filepath);
    }else{
        std::string login,pass;
        std::cout << "Введите логин: " << std::endl;
        std::cin >> login;
        std::cout << "Введите пароль: " << std::endl;
        std::cin >> pass;
        reg_user(clientSocket,login,pass);
    }
    std::cout << "OK received" << std::endl;
    // Закрытие сокета
    close(clientSocket);
    std::cout << "Connection closed\n";

    return 0;
}
