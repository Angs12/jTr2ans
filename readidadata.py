def parse_operand(operator,location,operand1):
    operand1=operand1.strip(' ')
    for p in ('ptr ','offset ','xmmword ','dword ','qword ','word ','byte ','short '):
        operand1 = operand1.replace(p, '')
    operand1 = operand1.replace('-','+')

    if operand1[:3] in {'cs:','ss:','fs:','ds:','es:','gs:'}:
        operand1 = operand1[:3] + 'xxx'
        return operand1
    if operator[0]=='j' and not isregister(operand1):
        if operand1[0:4]=='loc_' or operand1[0:7]=='locret_' or operand1[0:4]=='sub_' :
            operand1='hex_'+operand1[operand1.find('_')+1:]
            return operand1
        else:
            #print("JUMP ",operand1)
            operand1='UNK_ADDR'
            return operand1

    if operand1[0:4]=='loc_' :
        operand1='loc_xxx'
        return operand1
    if operand1[0:4]=='off_' :
        operand1='off_xxx'
        return operand1
    if operand1[0:4]=='unk_' :
        operand1='unk_xxx'
        return operand1
    if operand1[0:6]=='locret' :
        operand1='locretxxx'
        return operand1
    if operand1[0:4]=='sub_' :
        operand1='sub_xxx'
        return operand1
    if operand1[0:4]=='arg_' :
        operand1='arg_xxx'
        return operand1
    if operand1[0:4]=='def_' :
        operand1='def_xxx'
        return operand1
    if operand1[0:4]=='var_' :
        operand1='var_xxx'
        return operand1
    if operand1[0]=='(' and operand1[-1]==')':
        operand1='CONST'
        return operand1
    if operator=='lea' and location==2:
        if not ishexnumber(operand1) and not isaddr(operand1):  #handle some address constants
            operand1='GLOBAL_VAR'
            return operand1

    if operator=='call' and location==1:
        if len(operand1)>3:
            operand1='callfunc_xxx'
            return operand1

    if operator=='extrn':
        operand1='extrn_xxx'
        return operand1
    if ishexnumber(operand1):
        operand1='CONST'
        return operand1
    elif ispurenumber(operand1):
        operand1='CONST'
        return operand1
    if isaddr(operand1):
        params=operand1[1:-1].split('+')
        for i in range(len(params)):
            if ishexnumber(params[i]):
                params[i]='CONST'
            elif ispurenumber(params[i]):
                params[i]='CONST'
            elif params[i][0:4]=='var_':
                params[i]='var_xxx'
            elif params[i][0:4]=='arg_':
                params[i]='arg_xxx'
            elif not isregister(params[i]):
                if params[i].find('*')==-1:
                    params[i]='CONST_VAR'
        s1='+'
        operand1='['+s1.join(params)+']'
        return operand1

    if not isregister(operand1) and len(operand1)>4:
        operand1='CONST'
        return operand1
    return operand1
def parse_asm(code):
    annotation = None
    operator, operand = None, None
    operand1, operand2, operand3 = None, None, None
    code, _, annotation = code.partition(';')
    annotation = annotation or None
    parts = code.split(' ', maxsplit=1)
    operator = parts[0]
    operand = parts[1] if len(parts) > 1 else None
    if operand is not None:
        operand1, *rest = operand.split(',')
        operand2 = rest[0] if rest else None
        operand3 = rest[1] if len(rest) > 1 else None
    if operand1 is not None:
        operand1 = parse_operand(operator, 1, operand1)
    if operand2 is not None:
        operand2 = parse_operand(operator, 2, operand2)
    if operand3 is not None:
        operand3 = parse_operand(operator, 3, operand3)
    return operator, operand1, operand2, operand3, annotation
def isregister(x):
    return x in {'rax','rbx','rcx','rdx','esi','edi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15'}
def ispurenumber(number):
    if len(number)==1 and str.isdigit(number):
        return True
    return False
def isaddr(number):
    return number.startswith('[') and number.endswith(']')
def ishexnumber(number):
    return number[-1] == 'h' and all(str.isdigit(c) or 'A' <= c <= 'F' for c in number[:-1])

