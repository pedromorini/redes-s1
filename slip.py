class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.recebido = bytearray(b'')
        self.aux = bytearray(b'')

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        # TODO: Preencha aqui com o código para enviar o datagrama pela linha
        # serial, fazendo corretamente a delimitação de quadros e o escape de
        # sequências especiais, de acordo com o protocolo CamadaEnlace (RFC 1055).
        # Realiza o escape dos bytes 0xC0 e 0xDB no datagrama
        datagrama_escaped = datagrama.replace(b'\xDB', b'\xDB\xDD').replace(b'\xC0', b'\xDB\xDC')
        # Insere o byte 0xC0 no começo e no fim do datagrama
        datagrama_com_delimitadores = b'\xC0' + datagrama_escaped + b'\xC0'
        # Envia o datagrama pela linha serial
        self.linha_serial.enviar(datagrama_com_delimitadores)

    def __raw_recv(self, dados):
        # TODO: Preencha aqui com o código para receber dados da linha serial.
        # Trate corretamente as sequências de escape. Quando ler um quadro
        # completo, repasse o datagrama contido nesse quadro para a camada
        # superior chamando self.callback. Cuidado pois o argumento dados pode
        # vir quebrado de várias formas diferentes - por exemplo, podem vir
        # apenas pedaços de um quadro, ou um pedaço de quadro seguido de um
        # pedaço de outro, ou vários quadros de uma vez só.
        for i in range(len(dados)):
            if (bytes(dados[i:i+1]) != b'\xC0') & (bytes(dados[i:i+1]) != b'\xDC') & (bytes(dados[i:i+1]) != b'\xDD') & (bytes(dados[i:i+1]) != b'\xDB'):
                self.recebido += dados[i:i+1]
                            
            elif (bytes(dados[i:i+1]) == b'\xDB'):
                
                if (bytes(dados[i+1:i+2]) == b'\xDC'):
                    self.recebido += bytearray(b'\xC0')
                elif (bytes(dados[i+1:i+2]) == b'\xDD'):
                    self.recebido += dados[i:i+1]
                    self.aux = bytearray(b'')
                elif (i+1) == len(dados):
                    self.aux = bytearray(b'\xDB')
                    
            elif (bytes(dados[i:i+1]) == b'\xDD') & (self.aux == b'\xDB'):       
                self.recebido += self.aux
                self.aux = bytearray(b'')
            
            elif (bytes(dados[i:i+1]) == b'\xDC') & (self.aux == b'\xDB'):
                self.recebido += bytearray(b'\xC0')
           
           # Enviar Recebido
           
            elif (len(dados) >= 1) & (len(dados) == (i+1)) & (self.recebido != bytearray(b'')) & (bytes(dados[i:i+1]) == b'\xC0'):
                
                try:
                    self.callback(bytes(self.recebido))
                except:
                    # ignora a exceção, mas mostra na tela
                    import traceback
                    traceback.print_exc()
                finally:
                    # faça aqui a limpeza necessária para garantir que não vão sobrar
                    # pedaços do datagrama em nenhum buffer mantido por você
                    self.recebido = bytearray(b'')
                    self.aux = bytearray(b'')
                
           
            elif (bytes(dados[i:i+1]) == b'\xC0') & (self.recebido != bytearray(b'')):
                try:
                    self.callback(bytes(self.recebido))
                except:
                    # ignora a exceção, mas mostra na tela
                    import traceback
                    traceback.print_exc()
                finally:
                    # faça aqui a limpeza necessária para garantir que não vão sobrar
                    # pedaços do datagrama em nenhum buffer mantido por você
                    self.recebido = bytearray(b'')
                    self.aux = bytearray(b'')
