################################################################################
#                                  Mitchel Herman                              #
#                                    Assembler                                 #
#                                Started: 11/18/16                             #
#                                   Due: 12/11/16                              #
# Python 2 pass assembler for SIC/XE arcitecture                               #
# Takes a .asm file with SIC/XE assembly code and creates a .exe file          #
# with all of the bytes for the object codes for the code as well as writes to #
# standard output all of the lines of the asm file with their corresponding    #
# offsets and object codes                                                     #
################################################################################

import sys

################################################################################
#                                  Global Variables                            #
################################################################################

#Declaring global variables for clean indexing:

#To index tuple after calling lookup_mnemonic()
TYPE = 0
FORMAT = 1
OPCODE = 2
OPERANDTYPE = 3

#To index tuple after calling seperate(row)
LABEL = 0
MNEMONIC = 1
OPERANDFIELD = 2
COMMENT = 3

#Dictionary for mnemonics:
#Format will follow: {"MNEMONIC" : (type, format, opcode, operand)}
MNEMS = {
    "LDA":('i', 3, 0x00, "m"),
    "ADD":('i', 3, 0x18, "m"),
    "ADDR":('i', 2, 0x90, "rr"),
    "AND":('i', 3, 0x40, "m"),
    "CLEAR":('i', 2, 0xb4, "r"),
    "COMP":('i', 3, 0x28, "m"),
    "COMPR":('i', 2, 0xa0, "rr"),
    "DIV":('i', 3, 0x24, "m"),
    "DIVR":('i', 2, 0x9c, "rr"),
    "HIO":('i', 1, 0xf4, ""),
    "J":('i', 3, 0x3c, "m"),
    "JEQ":('i', 3, 0x30, "m"),
    "JGT":('i', 3, 0x34, "m"),
    "JLT":('i', 3, 0x38, "m"),
    "JSUB":('i', 3, 0x48, "m"),
    "LDB":('i', 3, 0x68, "m"),
    "LDCH":('i', 3, 0x50, "m"),
    "LDF":('i', 3, 0x70, "m"),
    "LDL":('i', 3, 0x08, "m"),
    "LDS":('i', 3, 0x6c, "m"),
    "LDT":('i', 3, 0x74, "m"),
    "LDX":('i', 3, 0x04, "m"),
    "LPS":('i', 3, 0xd0, "m"),
    "MUL":('i', 3, 0x20, "m"),
    "MULR":('i', 2, 0x98, "rr"),
    "OR":('i', 3, 0x44, "m"),
    "RD":('i', 3, 0xd8, "m"),
    "RMO":('i', 2, 0xac, "rr"),
    "RSUB":('i', 3, 0x4c, "m"),
    "SHIFTL":('i', 2, 0xa4, "rn"),
    "SHIFTR":('i', 2, 0xa8, "rn"),
    "SIO":('i', 1, 0xf0, ""),
    "SSK":('i', 3, 0xec, "m"),
    "STA":('i', 3, 0x0c, "m"),
    "STB":('i', 3, 0x78, "m"),
    "STCH":('i', 3, 0x54, "m"),
    "STI":('i', 3, 0xd4, "m"),
    "STL":('i', 3, 0x14, "m"),
    "STS":('i', 3, 0x7c, "m"),
    "STSW":('i', 3, 0xe8, "m"),
    "STT":('i', 3, 0x84, "m"),
    "STX":('i', 3, 0x10, "m"),
    "SUB":('i', 3, 0x1c, "m"),
    "SUBR":('i', 2, 0x94, "rr"),
    "SVC":('i', 2, 0xb0, "n"),
    "TD":('i', 3, 0xe0, "m"),
    "TIO":('i', 1, 0xf8, ""),
    "TIX":('i', 3, 0x2c, "m"),
    "TIXR":('i', 2, 0xb8, "r"),
    "WD":('i', 3, 0xdc, "m"),
    "RESB":('d', 1),
    "RESW":('d', 3),
    "BYTE":('d', None),
    "WORD":('d', 3),
    "BASE":('a'),
    "START":('a'),
    "END":('a')
    }

#Dictionary for the Symbol table. Will be loaded durring first pass
#Format will be {label:offset}
symbTab = {}

################################################################################
#                            Simple Helper Functions                           #
################################################################################

def error(message):
    """Helper function to print an error message"""
    print(message)
    sys.exit()

def lookup_mnemonic(mnemonic):
    """Returns the tuple of information for the mnemonic"""
    try:
        return MNEMS[mnemonic]
    except(KeyError):
        error("mnemonic not valid")

def loadSymbTab(row, offset):
    """Given a row, if it has a symbol, it loads the offset of the symbol into a
    symbol table"""
    if row[LABEL] != "":
        if row[LABEL] not in symbTab:
            symbTab[row[LABEL]] = offset
        else:
            error("Label used more than once")

def notCommentLine(label):
    """Checks to see if the given line is not a comment line"""
    return label == '' or label[0] != '.'

def valid_plus(mnemonic):
    """Given a mnemonic with a plus, it sees if it's a valid mnemonic"""
    return lookup_mnemonic(base_mnemonic(mnemonic))[1] == 3

def ThreeOrFour(label):
    """Determines if menumonic should be interpreted as a format 3 or 4"""
    if '+' in label:
        return 4
    return 3

def twosComp(bitString):
    """Does twos compliment negation on a bitstring"""
    negation = ""
    for bit in bitString:
        if bit == '0':
            negation += '1'
        else:
            negation += '0'

    negation = bin(int(negation,2) + 1)[2:]
    return negation

################################################################################
#                               Calculating Offsets                            #
################################################################################

def rowLenBytes(info, row):
    """Given the info of the mnem from the dictionary,
        it returns the len in bytes"""
    if info[TYPE] == 'i': #If it's an instruction, retun theformat
        return info[FORMAT]
    elif info[TYPE] == 'd': #If it's a data decleration
        if row[MNEMONIC] == 'RESB': #To reserve bytes
            return hex(int(row[OPERANDFIELD])) #look at the operand
        elif row[MNEMONIC] == 'RESW': #To reserve a word
            return hex(int(row[OPERANDFIELD]) * 3) #3 * the operand
        else: #To declare a byte or a word
            return info[FORMAT] #retun the info at [1]
    else: #For assembler instructions
        return 0

def calcOffset(current, adding):
    """Adds current offset to adding, in hex"""
    try:
        new = int(current,16)+ adding
    except(TypeError):
        new = int(current,16) + int(adding,16)
    return hex(new)

def offsetDifference(start, end):
    """Calculates offset difference"""
    dif = end - int(start, 16)
    return dif

################################################################################
#                                   Formating                                  #
################################################################################

def seperate(line):
    """create strings for each and return them in a tuple"""
    label = ""
    mnemonic = ""
    args =""
    comments =""
    #list all of sections
    sections = [label,mnemonic,args, comments]
    i=0
    fin = []
    for section in sections:
        #Stop for new line, tabs, and spaces
        while i < len(line) and  line[i] != ' ' \
        and line[i] != '\t' and line[i] != '\n':
            section += line[i]
            i += 1
        fin.append(section)
        i += 1
        #While loop to ignore extra spaces and tabs
        while i<len(line):
            if line[i] == ' ' or  line[i] == '\t':
                i+= 1
            else:
                break
    return fin

def F2Split(row):
    """Splits up the operand field into it's individual operands"""
    one = ""
    two = ""
    sections = [one,two]
    fin = []
    i = 0
    for section in sections:
        #Stop for new line, tabs, and spaces
        while i < len(row[OPERANDFIELD]) and  row[OPERANDFIELD][i] != ',':
            section += row[OPERANDFIELD][i]
            i += 1
        fin.append(section)
        i += 1

    return fin

def baseOperand(operand):
    """returns the Operand without @,#, or ,X"""
    if operand[0] == '#' or operand[0] == '@':
        operand = operand[1:]
    if operand[len(operand)-2:len(operand)] == ",X":
        operand = operand [0:-2]
    return operand

def hexToByte(hexString):
    """Convert a string hex values into a string of Chars."""
    bytes = []

    for i in range(0, len(hexString), 2):
        bytes.append(chr(int(hexString[i:i+2],16)))

    return ''.join(bytes)

def base_mnemonic(mnemonic):
    """Removes the + if necessary"""
    if(mnemonic[0] == '+'):
        return mnemonic[1:]
    return mnemonic

################################################################################
#                               Object Code Calculation                        #
################################################################################

def getObjectCode(row, info, PC, BASE, byteLen):
    """Gets the object code of a non comment 'i' type row"""
    #Special case for RSUB(Format 3 with no operands)
    if row[MNEMONIC] == "RSUB":
        return "4f0000"

    #Format 3/4
    if byteLen == 3 or byteLen == 4:
        op = hex(int(info[OPCODE]) + ni(row)) #Get OP + NI bits
        xbpeString = xbpe(row,info,PC,BASE) #Get XBPE string
        if xbpeString[3] == '1':
            num = 6 #Address
        else:
            num = 4 #Displacement
        #Get the displacement/address
        disp = dispOrAddr(PC,BASE,xbpeString,row[OPERANDFIELD],ni(row))
        objectCode = op.zfill(2) + hex(int(xbpeString + disp, 2))[2:].zfill(num)

    #Format 1
    if byteLen == 1:
        return hex(int(info[OPCODE]))[2:].zfill(2*byteLen)

    #Format 1
    if byteLen == 2:
        op = hex(int(info[OPCODE])) + format_2_regs(row,info)
        objectCode = op

    return objectCode[2:].zfill(2 * byteLen)


def ni(row):
    """Gets the object code of a non comment 'i' type row"""
    n = False
    i = False
    if '@' in row[OPERANDFIELD]: #@ = n bit set
        n = True
    if '#' in row[OPERANDFIELD]: # #= i bit set
        i = True
    if n and i: # if both are there, thats not legal
        error("Line both immediate and indirect")

    if n:
        return 2 # 10 in binary
    elif i:
        return 1 #01 in binary
    else: #neither were set = direct
        return 3 # 11 in binary

def xbpe(row, info, PC, BASE):
    """Gets XBPE for format 3. Returns as the bitstring"""
    x = False
    b = False
    p = False
    e = False

    if ",X" in row[OPERANDFIELD]: #,X means the X bit needs to be set
        x = True
    if row[MNEMONIC][0] == '+': # +mnemoinic means the e bit should be set
        e = True
    else:
        #Determine if the b or p bits need to be set still
        if baseOperand(row[OPERANDFIELD]) in symbTab:
            distance = offsetDifference(PC, \
                int(symbTab[baseOperand(row[OPERANDFIELD])], 16))
            if distance >= -2048 and distance <= 2047:
                p = True
            elif BASE != None:
                baseDistance =offsetDifference(BASE, \
                    int(symbTab[baseOperand(row[OPERANDFIELD])], 16))
                if baseDistance >= 0 and baseDistance <= 4095:
                    b = True
                else:
                    error("Base and PC too far away from symbol")
            else:
                error("PC top far away from symbol, and Base not set")

    # append bits to the bitstring for each bit
    bitString = ""
    if x:
        bitString = bitString + '1'
    else:
        bitString = bitString + '0'
    if b:
        bitString = bitString + '1'
    else:
        bitString = bitString + '0'
    if p:
        bitString = bitString + '1'
    else:
        bitString = bitString + '0'
    if e:
        bitString = bitString + '1'
    else:
        bitString = bitString + '0'

    return bitString

def dispOrAddr(PC, BASE, xbpeString, operand,niVal):
    """Get the last 12 (or 20) bits for format 3/4"""
    #PC relative
    if xbpeString[2] == '1':
        begin = PC
        bitnum = 12
    #BASE relative
    elif xbpeString[1] == '1':
        begin = BASE
        bitnum = 12
    #Extended
    elif xbpeString[3] == '1':
        bitnum = 20
        #If Immediate decimal value
        if niVal == 1 and baseOperand(operand) not in symbTab:
            return bin(int(baseOperand(operand)))[2:].zfill(bitnum)
        #If offset address
        return bin(int(symbTab[baseOperand(operand)],16))[2:].zfill(bitnum)
    #Immediate
    else:
        return bin(int(baseOperand(operand)))[2:].zfill(12)

    #Calculate diffrence in offset
    end = symbTab[baseOperand(operand)]
    disp = (bin(offsetDifference(begin,int(end,16))))

    #if needed: do a twos compliment negation of bits
    if disp[0] == '-':
        disp = twosComp(disp[3:].zfill(bitnum))
        return disp.zfill(bitnum)
    return disp[2:].zfill(bitnum)

def format_2_regs(row, info):
    """Gets the extra bits for format 2"""
    REGISTERS = {'A':'0', 'X':'1', 'L':'2', "PC":'8', "SW":'9',
            'B':'3', 'S':'4', 'T':'5', 'F': '6'}
    f2disp = ""
    split = F2Split(row) #Get the operands

    #Two registers
    if info[OPERANDTYPE] == "rr":
        for item in split:
            f2disp += REGISTERS[item]
    #One register and nothing else
    if info[OPERANDTYPE] == "r":
        f2disp += REGISTERS[split[0]]
        f2disp += '0'
    #One register and one number
    elif info[OPERANDTYPE] =="rn":
        f2disp += REGISTERS[split[0]]
        f2disp += hex(int(split[1])-1)[2:]
    #Just one number
    elif info[OPERANDTYPE] == "n":
        f2disp += str(int(row[OPERANDFIELD])) + '0'

    return f2disp

################################################################################
#                                   Main Algorithms                            #
################################################################################

def firstPass(filename):
    """Does the first pass: creates symbol table """
    offset = '0x0' #Current offset in hex
    inFile = open(filename, 'r')
    end = False
    start = False

    for line in inFile:
        row = seperate(line)#Returns tuple: (Label, Mnemonic, Operands, Coms)
        if start == False:
            if notCommentLine(row[LABEL]):
                if row[MNEMONIC] == "START":
                    offset = "0x" + str(row[OPERANDFIELD])
                else:
                    offset = "0x0"
                start = True
        if notCommentLine(row[LABEL]):
            #Returns tuple from Dictionary with information about mnemonic
            info = lookup_mnemonic(base_mnemonic(row[MNEMONIC]))

            if row[MNEMONIC] != base_mnemonic(row[MNEMONIC]): #If there is a +
                #Check to see if its valid plus
                if valid_plus(row[MNEMONIC]) == False:
                    error(" '+' used on non format 3/4 menmonic at offset," \
                        + offset) #if not, throw an error

            adding = rowLenBytes(info, row) #Calculates the len, in bytes
        #If Dictionary has a 3 for byte len of mnemonic, then check to see if 4
            if adding == 3:
                adding = ThreeOrFour(row[MNEMONIC]) #row[MNEMONIC] is the menem
            if adding == None:
                adding = len(row[OPERANDFIELD]) - 3
                if row[OPERANDFIELD][0] == 'X':
                    adding = adding // 2

            loadSymbTab(row,offset) #Load the symbTab if necessary

            offset = calcOffset(offset,adding) #calculate new offset

    for item in symbTab:
        print('\t' + item + '\t' + str(symbTab[item]))

def secondPass(filename):
    """Does the second pass (Creates Object codes)"""
    PC = '0x0'
    offset = '0x0'
    BASE = None
    inFile = open(filename,'r')
    output = open(filename[:-4] + ".exe",'w')
    start = False

    for line in inFile:
        row = seperate(line)

        #Get the Starting Offset
        if start == False:
            if notCommentLine(row[LABEL]):
                if row[MNEMONIC] == "START":
                    offset = "0x" + str(row[OPERANDFIELD])
                else:
                    offset = "0x0"
                start = True
        else:
            start = True
        if notCommentLine(row[LABEL]):
            info = lookup_mnemonic(base_mnemonic(row[MNEMONIC]))
            #Calculates the len, in bytes, of current line
            adding = rowLenBytes(info, row)
        #If Dictionary has a 3 for byte len, then heck to see if it's actually 4
            if adding == 3:
                adding = ThreeOrFour(row[MNEMONIC])
            if adding == None: #MNEMONIC = BYTE
                adding = len(row[OPERANDFIELD]) - 3 #Get the len of the operand
                if row[OPERANDFIELD][0] == 'X': #If its in hex,
                    adding = adding // 2 #Divide by 2
            PC = calcOffset(PC,adding) #Calculate the new PC

            #Instructions
            if info[TYPE] == 'i':
                #Get the Object code, output it, and print to std output
                objectCode = getObjectCode(row,info,PC,BASE, adding)

                print(str(offset[2:].zfill(5)) + '\t'+ row[LABEL] + '\t' + \
                row[MNEMONIC]+ '\t'+ row[OPERANDFIELD] + '\t'+ \
                row[COMMENT] + '\t',objectCode)

                output.write(hexToByte(objectCode))

            #Data Declarations
            elif info[TYPE] == 'd':
                hexString = ""

                #RESB Reserve byte by placing a byte of 0's
                if row[MNEMONIC] == "RESB":
                    for _ in range(int(rowLenBytes(info,row), 16)):
                        hexString += "00"

                    print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL] + '\t' \
                          + row[MNEMONIC] + '\t'+ row[OPERANDFIELD] +\
                          '\t'+ row[COMMENT])

                #RESW reserve word by placing three bytes of 0's
                if row[MNEMONIC] == "RESW":
                    for _ in range(int(rowLenBytes(info,row) , 16)):
                        hexString += "00"

                    print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL] + '\t'\
                         + row[MNEMONIC] + '\t'+ row[OPERANDFIELD] + \
                          '\t'+ row[COMMENT])

                #WORD should be outputed as the hex of the operand field
                #filling 6 nibbles
                if row[MNEMONIC] == "WORD":
                    hexString = hex(int(row[OPERANDFIELD]))[2:].zfill(6)

                    print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL] + '\t' \
                        + row[MNEMONIC] + '\t'+ row[OPERANDFIELD] + '\t'+ \
                          row[COMMENT] + '\t',hexString)

                #BYTE should be saved diffrently for hex and ascii
                if row[MNEMONIC] == "BYTE":
                    #If it's hex. Output the ascii inside the X' '
                    if row[OPERANDFIELD][0] == 'X':
                        hexString = row[OPERANDFIELD][2:-1]

                        print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL] +\
                        '\t' + row[MNEMONIC] + '\t'+ row[OPERANDFIELD] + '\t'+\
                        row[COMMENT] + '\t',hexString)

                    #If it's ascii: translate the chars into the hex of chars
                    elif row[OPERANDFIELD][0] == 'C':
                        for char in row[OPERANDFIELD][2:-1]:
                            hexString += hex(ord(char))[2:]

                        print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL]\
                              + '\t' + row[MNEMONIC] + '\t'+ \
                              row[OPERANDFIELD] + '\t'+ row[COMMENT]\
                              + '\t',hexString)

                output.write(hexToByte(hexString))

            #Assembler Instructions
            elif info[TYPE] == 'a':
                #BASE sets the BASE value
                if row[MNEMONIC] == "BASE":
                    BASE = symbTab[row[OPERANDFIELD]]
                #END stops the assembler
                if row[MNEMONIC] == "END":
                    print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL]\
                     + '\t' + row[MNEMONIC] + '\t'+ \
                      row[OPERANDFIELD] + '\t'+ row[COMMENT])
                    sys.exit()
                #NOBASE clears the base
                if row[MNEMONIC] == "NOBASE":
                    BASE = None
                print(str(offset[2:].zfill(5)) + '\t'+  row[LABEL]\
                     + '\t' + row[MNEMONIC] + '\t'+ \
                      row[OPERANDFIELD] + '\t'+ row[COMMENT])



            offset = hex(int(PC, 16))

        #Comment Lines
        else:
            print(line)

def main():
    filename = sys.argv[1]
    firstPass(filename)
    secondPass(filename)

if __name__ == "__main__":
    main()
