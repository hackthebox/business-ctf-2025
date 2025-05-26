#include <iostream>
#include <unordered_map>
#include <string>

int main() {
    std::unordered_map<std::string, int> keyword_weights = {
        {"scan", 1},
        {"response", 2},
        {"control", 3},
        {"callback", 4},
        {"implant", 5},
        {"zombie", 6},
        {"trigger", 7},
        {"infected", 8},
        {"compromise", 9},
        {"inject", 10},
        {"execute", 11},
        {"deploy", 12},
        {"malware", 13},
        {"exploit", 14},
        {"payload", 15},
        {"backdoor", 16},
        {"zeroday", 17},
        {"botnet", 18}
    };

    std::string data;
    std::getline(std::cin, data);  // Read the full input line
    int ans = 0;

    for (const auto& [keyword, weight] : keyword_weights) {
        size_t pos = 0;
        while ((pos = data.find(keyword, pos)) != std::string::npos) {
            ans += weight;
            pos += keyword.length();  // Move past this keyword occurrence
        }
    }

    std::cout << ans << std::endl;
    return 0;
}
