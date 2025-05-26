#include <iostream>
#include <vector>
#include <string>
#include <bitset>
using namespace std;

// Reads the next n binary digits from stdin as a string and returns its integer value
int read_binary(int n) {
    string s;
    char c;
    while (s.length() < n && cin.get(c)) {
        if (c == '0' || c == '1') {
            s += c;
        }
    }
    return bitset<32>(s).to_ulong(); // supports up to 32 bits
}

int main() {
    int T, L;
    cin >> T >> L;

    cin.ignore(); // consume newline or whitespace

    vector<int> transitions(T, 0);
    for (int i = 0; i < T; ++i) {
        int state = read_binary(12);
        int opcode = read_binary(8);
        transitions[state] = opcode;
    }

    vector<int> opcode_exec_stream;
    for (int i = 0; i < L; i += 8) {
        int opcode = read_binary(8);
        opcode_exec_stream.push_back(opcode);
    }

    int m = L / 8;
    vector<vector<long long>> dp(m + 1, vector<long long>(T + 1, 0));
    
    for (int i = 0; i <= m; ++i) {
        dp[i][0] = 1;
    }

    for (int i = 1; i <= m; ++i) {
        for (int j = 1; j <= T; ++j) {
            if (opcode_exec_stream[i - 1] == transitions[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1] + dp[i - 1][j];
            } else {
                dp[i][j] = dp[i - 1][j];
            }
        }
    }

    cout << dp[m][T] << endl;
    return 0;
}
