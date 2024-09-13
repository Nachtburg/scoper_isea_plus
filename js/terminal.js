const output = document.getElementById('output');
const commands = [
    '┌──(Hexe🌑Nachtburg)-[~]' ,
    '└─$ git clone https://github.com/Nachtburg/scoper_isea_plus.git  ',
    '┌──(Hexe🌘Nachtburg)-[~]' ,
    '└─$ cd scoper_isea_plus  ',
    '┌──(Hexe🌗Nachtburg)-[~/scoper_isea_plus]' ,
    '└─$ python3 -m venv .venv  ',
    '┌──(Hexe🌖Nachtburg)-[~/scoper_isea_plus]' ,
    '└─$ source .venv/bin/activate  ',
    '┌──(.venv)─(Hexe🌕Nachtburg)-[~/scoper_isea_plus]' ,
    '└─$ pip install -U pip  ',
    '┌──(.venv)─(Hexe🌔Nachtburg)-[~/scoper_isea_plus]' ,
    '└─$ pip install -r requirements.txt  ',
    '┌──(.venv)─(Hexe🌓Nachtburg)-[~/scoper_isea_plus]' ,
    '└─$ python scoper.py -d /path/to/directory ',
    '┌──(.venv)─(Hexe🌒Nachtburg)-[~/scoper_isea_plus]' ,
    '└─$ sudo python scoper.py -d /path/to/directory ',
];

function typeCommand(command, callback) {
    let index = 0;
    const interval = setInterval(() => {
        if (index >= command.length) {
            clearInterval(interval);
            if (callback) callback();
        } else {
            output.textContent += command[index++];
        }
    }, 50);
}

function executeCommands(index) {
    if (index >= commands.length) return;
    typeCommand(commands[index], () => {
        setTimeout(() => {
            output.textContent += '\n';
            if (index + 1 < commands.length) {
                typeCommand(commands[index + 1], () => {
                    setTimeout(() => {
                        output.textContent += '... Executing\n';
                        executeCommands(index + 2);
                    }, 500);
                });
            } else {
                setTimeout(() => {
                    output.textContent += '... Executing\n';
                    executeCommands(index + 1);
                }, 500);
            }
        }, 500);
    });
}

executeCommands(0);
