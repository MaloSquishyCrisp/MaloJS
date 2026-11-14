/**
 * 
 * FEATURES:
 * 1. Settings & Control Area: Simple API to tune memory limits and GC behavior.
 * 2. Mark-and-Sweep GC: Automatically reclaims unreachable heap objects.
 * 3. Security Compliance: Memory bounds and watchdog execution limits.
 * 4. High Speed: Optimized object lookups and O(1) stack operations.
 * ============================================================================
 */

// ==========================================
// 0. CLEAR SETTINGS & CONFIGURATION AREA
// ==========================================
/**
 * Modify these runtime parameters to tune performance, security thresholds,
 * and memory management behavior for your sandbox environment.
 */
const EngineSettings = {
    // Memory & Resource Security Limits
    maxScriptLength: 100000,         // Max characters allowed in source code
    maxInstructions: 1000000,        // Watchdog limit to prevent infinite loops (DoS)
    maxRecursionDepth: 256,          // Guard against stack overflow exploits

    // Garbage Collection Settings
    gcAllocationThreshold: 50,       // Trigger automatic GC after every N heap allocations
    enableAutoGC: true,              // Toggle automatic garbage collection sweeps
    debugGC: true                    // Log memory stats and GC collection cycles to console
};


// ==========================================
// 1. LEXER (TOKENIZER) WITH BOUNDS CHECKING
// ==========================================
const TokenType = {
    KEYWORD: 'KEYWORD',
    IDENTIFIER: 'IDENTIFIER',
    NUMBER: 'NUMBER',
    STRING: 'STRING',
    OPERATOR: 'OPERATOR',
    PUNCTUATION: 'PUNCTUATION',
    EOF: 'EOF'
};

class SecureTokenizer {
    constructor(input, settings) {
        if (typeof input !== 'string' || input.length > settings.maxScriptLength) {
            throw new Error("SecurityError: Input exceeds maximum allowed script length.");
        }
        this.input = input;
        this.cursor = 0;
    }

    tokenize() {
        const tokens = [];
        const length = this.input.length;

        while (this.cursor < length) {
            let char = this.input[this.cursor];

            if (/\s/.test(char)) {
                this.cursor++;
                continue;
            }

            if (char === '/' && this.input[this.cursor + 1] === '/') {
                while (this.cursor < length && this.input[this.cursor] !== '\n') {
                    this.cursor++;
                }
                continue;
            }

            if (/[a-zA-Z_]/.test(char)) {
                let value = '';
                while (this.cursor < length && /[a-zA-Z0-9_]/.test(this.input[this.cursor])) {
                    value += this.input[this.cursor++];
                }
                const type = ['let', 'fn', 'if', 'else', 'while', 'print', 'return'].includes(value)
                    ? TokenType.KEYWORD
                    : TokenType.IDENTIFIER;
                tokens.push({ type, value });
                continue;
            }

            if (/[0-9]/.test(char)) {
                let value = '';
                while (this.cursor < length && /[0-9.]/.test(this.input[this.cursor])) {
                    value += this.input[this.cursor++];
                }
                tokens.push({ type: TokenType.NUMBER, value: Number(value) });
                continue;
            }

            if (char === '"' || char === "'") {
                let quote = char;
                this.cursor++;
                let value = '';
                while (this.cursor < length && this.input[this.cursor] !== quote) {
                    value += this.input[this.cursor++];
                }
                if (this.cursor >= length) {
                    throw new Error("SyntaxError: Unterminated string literal.");
                }
                this.cursor++;
                tokens.push({ type: TokenType.STRING, value });
                continue;
            }

            const twoChar = char + (this.input[this.cursor + 1] || '');
            if (['==', '!=', '<=', '>=', '&&', '||'].includes(twoChar)) {
                tokens.push({ type: TokenType.OPERATOR, value: twoChar });
                this.cursor += 2;
                continue;
            }

            if ('+-*/=<>!{}();,'.includes(char)) {
                const type = '+-*/=<>!'.includes(char) ? TokenType.OPERATOR : TokenType.PUNCTUATION;
                tokens.push({ type, value: char });
                this.cursor++;
                continue;
            }

            throw new Error(`SecurityError: Unexpected character '${char}' at index ${this.cursor}`);
        }

        tokens.push({ type: TokenType.EOF, value: null });
        return tokens;
    }
}


// ==========================================
// 2. GARBAGE COLLECTOR (MARK-AND-SWEEP HEAP)
// ==========================================
/**
 * Manages heap-allocated objects. Tracks references, marks reachable items
 * during a collection cycle, and sweeps away unreferenced memory to prevent leaks.
 */
class GarbageCollector {
    constructor(settings) {
        this.settings = settings;
        this.heap = new Map(); // Map of Heap Reference ID -> { value, marked }
        this.nextRefId = 1;
        this.allocationsSinceGC = 0;
    }

    /**
     * Allocates a new value on the secure managed heap.
     * Triggers automatic GC if the allocation threshold is breached.
     */
    allocate(value) {
        // Auto-GC check based on settings
        if (this.settings.enableAutoGC) {
            this.allocationsSinceGC++;
            if (this.allocationsSinceGC >= this.settings.gcAllocationThreshold) {
                this.collect();
            }
        }

        const refId = `ref_${this.nextRefId++}`;
        this.heap.set(refId, {
            value: value,
            marked: false
        });
        return refId;
    }

    /**
     * Simple API: Manually trigger a full Garbage Collection cycle (Mark and Sweep).
     */
    collect(roots = []) {
        if (this.settings.debugGC) {
            console.log(`[GC] Starting collection cycle. Heap size before: ${this.heap.size} objects.`);
        }

        // Phase 1: MARK reachable objects starting from root references (stack & globals)
        for (const root of roots) {
            this._markRecursive(root);
        }

        // Phase 2: SWEEP unreachable objects from the heap
        let collectedCount = 0;
        for (const [refId, obj] of this.heap.entries()) {
            if (obj.marked) {
                // Reset mark flag for the next cycle
                obj.marked = false;
            } else {
                // Unreachable - free from memory
                this.heap.delete(refId);
                collectedCount++;
            }
        }

        this.allocationsSinceGC = 0;

        if (this.settings.debugGC) {
            console.log(`[GC] Collection complete. Reclaimed ${collectedCount} objects. Heap size now: ${this.heap.size}.`);
        }
    }

    /**
     * Helper to recursively mark objects and nested properties.
     */
    _markRecursive(item) {
        if (typeof item === 'string' && this.heap.has(item)) {
            const heapObj = this.heap.get(item);
            if (!heapObj.marked) {
                heapObj.marked = true;
                // If the heap object contains nested references, mark them too
                if (typeof heapObj.value === 'object' && heapObj.value !== null) {
                    for (const val of Object.values(heapObj.value)) {
                        this._markRecursive(val);
                    }
                }
            }
        }
    }

    /**
     * Simple API: Returns current memory statistics for monitoring.
     */
    getStats() {
        return {
            totalAllocatedObjects: this.heap.size,
            allocationsSinceLastGC: this.allocationsSinceGC
        };
    }
}


// ==========================================
// 3. BYTECODE OPCODES
// ==========================================
const OpCode = {
    LOAD_CONST: 1,
    LOAD_NAME: 2,
    STORE_NAME: 3,
    ADD: 4,
    SUB: 5,
    MUL: 6,
    DIV: 7,
    EQ: 8,
    NEQ: 9,
    LT: 10,
    GT: 11,
    JUMP: 12,
    JUMP_IF_FALSE: 13,
    CALL_PRINT: 14,
    POP: 15,
    HALT: 16
};


// ==========================================
// 4. COMPILER (PARSER & BYTECODE GENERATOR)
// ==========================================
class SecureCompiler {
    constructor(tokens, settings) {
        this.tokens = tokens;
        this.settings = settings;
        this.pos = 0;
        this.bytecode = [];
        this.constants = [];
        this.recursionDepth = 0;
    }

    current() { return this.tokens[this.pos]; }
    advance() { return this.tokens[this.pos++]; }

    expect(type, value) {
        const token = this.advance();
        if (token.type !== type || (value !== undefined && token.value !== value)) {
            throw new Error(`ParseError: Expected ${type} '${value}', got ${token.type} '${token.value}'`);
        }
        return token;
    }

    compile() {
        while (this.current().type !== TokenType.EOF) {
            this.parseStatement();
        }
        this.emit(OpCode.HALT);
        return { bytecode: this.bytecode, constants: this.constants };
    }

    emit(op, arg = null) {
        this.bytecode.push({ op, arg });
        return this.bytecode.length - 1;
    }

    patchJump(index, target) {
        this.bytecode[index].arg = target;
    }

    addConstant(value) {
        this.constants.push(value);
        return this.constants.length - 1;
    }

    parseStatement() {
        const token = this.current();

        if (token.type === TokenType.KEYWORD && token.value === 'let') {
            this.advance();
            const nameToken = this.expect(TokenType.IDENTIFIER);
            
            if (['__proto__', 'constructor', 'prototype', 'eval'].includes(nameToken.value)) {
                throw new Error(`SecurityError: Forbidden variable identifier '${nameToken.value}'`);
            }

            this.expect(TokenType.OPERATOR, '=');
            this.parseExpression();
            this.expect(TokenType.PUNCTUATION, ';');
            this.emit(OpCode.STORE_NAME, nameToken.value);
        } 
        else if (token.type === TokenType.KEYWORD && token.value === 'print') {
            this.advance();
            this.expect(TokenType.PUNCTUATION, '(');
            this.parseExpression();
            this.expect(TokenType.PUNCTUATION, ')');
            this.expect(TokenType.PUNCTUATION, ';');
            this.emit(OpCode.CALL_PRINT);
        } 
        else if (token.type === TokenType.KEYWORD && token.value === 'while') {
            this.advance();
            const loopStart = this.bytecode.length;
            this.expect(TokenType.PUNCTUATION, '(');
            this.parseExpression();
            this.expect(TokenType.PUNCTUATION, ')');

            const jumpIfFalseIdx = this.emit(OpCode.JUMP_IF_FALSE, 0);
            this.expect(TokenType.PUNCTUATION, '{');
            while (this.current().value !== '}' && this.current().type !== TokenType.EOF) {
                this.parseStatement();
            }
            this.expect(TokenType.PUNCTUATION, '}');
            this.emit(OpCode.JUMP, loopStart);
            this.patchJump(jumpIfFalseIdx, this.bytecode.length);
        } 
        else {
            this.parseExpression();
            if (this.current().value === ';') {
                this.advance();
            }
            this.emit(OpCode.POP);
        }
    }

    parseExpression() {
        this.recursionDepth++;
        if (this.recursionDepth > this.settings.maxRecursionDepth) {
            throw new Error("SecurityError: Maximum expression nesting depth exceeded.");
        }
        this.parseAdditive();
        this.recursionDepth--;
    }

    parseAdditive() {
        this.parseMultiplicative();
        while (['+', '-'].includes(this.current().value)) {
            const op = this.advance().value;
            this.parseMultiplicative();
            this.emit(op === '+' ? OpCode.ADD : OpCode.SUB);
        }
    }

    parseMultiplicative() {
        this.parsePrimary();
        while (['*', '/'].includes(this.current().value)) {
            const op = this.advance().value;
            this.parsePrimary();
            this.emit(op === '*' ? OpCode.MUL : OpCode.DIV);
        }
    }

    parsePrimary() {
        const token = this.advance();
        if (token.type === TokenType.NUMBER || token.type === TokenType.STRING) {
            const cIdx = this.addConstant(token.value);
            this.emit(OpCode.LOAD_CONST, cIdx);
        } else if (token.type === TokenType.IDENTIFIER) {
            if (['__proto__', 'constructor', 'prototype'].includes(token.value)) {
                throw new Error(`SecurityError: Access to protected property '${token.value}' is restricted.`);
            }
            this.emit(OpCode.LOAD_NAME, token.value);
        } else if (token.type === TokenType.PUNCTUATION && token.value === '(') {
            this.parseExpression();
            this.expect(TokenType.PUNCTUATION, ')');
        } else {
            throw new Error(`ParseError: Unexpected token in expression: ${token.value}`);
        }
    }
}


// ==========================================
// 5. VIRTUAL MACHINE WITH GC INTEGRATION
// ==========================================
class SecureVirtualMachine {
    constructor(program, settings) {
        this.bytecode = program.bytecode;
        this.constants = program.constants;
        this.settings = settings;
        
        this.stack = [];
        this.globals = Object.create(null); // Sandboxed scope
        this.gc = new GarbageCollector(settings);
        
        this.ip = 0;
        this.instructionCount = 0;
    }

    /**
     * Simple API: Gathers all active roots from VM stack and global scope
     * and triggers a garbage collection sweep.
     */
    triggerGC() {
        const roots = [];
        // Gather roots from global variables
        for (const val of Object.values(this.globals)) {
            if (typeof val === 'string') roots.push(val);
        }
        // Gather roots from execution stack
        for (const val of this.stack) {
            if (typeof val === 'string') roots.push(val);
        }
        this.gc.collect(roots);
    }

    run() {
        const bytecode = this.bytecode;
        const constants = this.constants;
        const stack = this.stack;
        const globals = this.globals;
        
        while (this.ip < bytecode.length) {
            // Watchdog check to prevent infinite loop DoS
            if (++this.instructionCount > this.settings.maxInstructions) {
                throw new Error("SecurityError: Maximum instruction execution limit reached.");
            }

            const instr = bytecode[this.ip++];
            
            switch (instr.op) {
                case OpCode.LOAD_CONST: {
                    let val = constants[instr.arg];
                    // Allocate large data types or strings on the managed heap
                    if (typeof val === 'string') {
                        val = this.gc.allocate(val);
                    }
                    stack.push(val);
                    break;
                }

                case OpCode.LOAD_NAME:
                    if (!(instr.arg in globals)) {
                        throw new Error(`ReferenceError: '${instr.arg}' is not defined in sandbox.`);
                    }
                    stack.push(globals[instr.arg]);
                    break;

                case OpCode.STORE_NAME:
                    globals[instr.arg] = stack.pop();
                    break;

                case OpCode.ADD: {
                    const b = stack.pop();
                    const a = stack.pop();
                    
                    // Resolve heap values if needed for operation
                    const realA = typeof a === 'string' && this.gc.heap.has(a) ? this.gc.heap.get(a).value : a;
                    const realB = typeof b === 'string' && this.gc.heap.has(b) ? this.gc.heap.get(b).value : b;
                    
                    const result = realA + realB;
                    let storedResult = result;
                    if (typeof result === 'string') {
                        storedResult = this.gc.allocate(result);
                    }
                    stack.push(storedResult);
                    break;
                }

                case OpCode.SUB: {
                    const b = stack.pop();
                    const a = stack.pop();
                    const realA = typeof a === 'string' && this.gc.heap.has(a) ? this.gc.heap.get(a).value : a;
                    const realB = typeof b === 'string' && this.gc.heap.has(b) ? this.gc.heap.get(b).value : b;
                    stack.push(realA - realB);
                    break;
                }

                case OpCode.MUL: {
                    const b = stack.pop();
                    const a = stack.pop();
                    const realA = typeof a === 'string' && this.gc.heap.has(a) ? this.gc.heap.get(a).value : a;
                    const realB = typeof b === 'string' && this.gc.heap.has(b) ? this.gc.heap.get(b).value : b;
                    stack.push(realA * realB);
                    break;
                }

                case OpCode.DIV: {
                    const b = stack.pop();
                    const a = stack.pop();
                    const realA = typeof a === 'string' && this.gc.heap.has(a) ? this.gc.heap.get(a).value : a;
                    const realB = typeof b === 'string' && this.gc.heap.has(b) ? this.gc.heap.get(b).value : b;
                    if (realB === 0) throw new Error("RuntimeError: Division by zero.");
                    stack.push(realA / realB);
                    break;
                }

                case OpCode.CALL_PRINT: {
                    let val = stack.pop();
                    // Resolve heap references for printing
                    if (typeof val === 'string' && this.gc.heap.has(val)) {
                        val = this.gc.heap.get(val).value;
                    }
                    console.log("[Sandbox Output]:", val);
                    break;
                }

                case OpCode.JUMP:
                    this.ip = instr.arg;
                    break;

                case OpCode.JUMP_IF_FALSE:
                    if (!stack.pop()) {
                        this.ip = instr.arg;
                    }
                    break;

                case OpCode.POP:
                    stack.pop();
                    break;

                case OpCode.HALT:
                    return;

                default:
                    throw new Error(`RuntimeError: Invalid opcode: ${instr.op}`);
            }
        }
    }
}


// ==========================================
// 6. EXECUTE TEST WORKLOAD WITH GC
// ==========================================
const sourceCode = `
    let text = "Hello, Secure Garbage Collected VM!";
    let x = 10;
    let sum = 0;
    while (x > 0) {
        sum = sum + x;
        x = x - 1;
    }
    print(text);
    print(sum);
`;

console.log("=== Initializing Engine with Settings & GC ===");
try {
    const tokenizer = new SecureTokenizer(sourceCode, EngineSettings);
    const tokens = tokenizer.tokenize();
    
    const compiler = new SecureCompiler(tokens, EngineSettings);
    const program = compiler.compile();

    const vm = new SecureVirtualMachine(program, EngineSettings);
    vm.run();

    // Check GC memory stats using simple API
    console.log("=== VM Memory Stats ===", vm.gc.getStats());

    // Manually trigger a GC sweep test
    vm.triggerGC();

} catch (error) {
    console.error("Execution Error:", error.message);
}
