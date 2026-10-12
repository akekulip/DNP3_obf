"""Read the four observation banks without depending on BFRT field spelling."""

BANKS = ('tin', 'token', 'held', 'hb')
REGISTER_NAMES = tuple('p1.t_Ingress.outcomes_' + bank for bank in BANKS)


class Outcomes:
    def __init__(self, model, schema):
        self.model = model
        self.fields = {}
        tables = {table['name']: table for table in schema['tables']}
        for name in REGISTER_NAMES:
            table = tables[name]
            fields = [entry['singleton'] for entry in table['data']]
            if table['table_type'] != 'Register' or table['size'] != 25 or len(fields) != 1:
                raise ValueError('unexpected observation bank: ' + name)
            field = fields[0]
            if field['type'].get('width') != 32:
                raise ValueError('observation bank is not 32 bits: ' + name)
            self.fields[name] = field['name']

    def read(self, bank, index):
        if bank not in BANKS or type(index) is not int or not 0 <= index < 25:
            raise ValueError('invalid outcome bank/index')
        name = 'p1.t_Ingress.outcomes_' + bank
        result = self.model.register_read(name, index, pipe=1)
        field = self.fields[name]
        data = {key: value for key, value in result.items()
                if key not in ('action_name', 'is_default_entry')}
        if set(data) != {field}:
            raise ValueError('missing or unexpected register field: ' + name)
        value = data[field]
        if isinstance(value, list):
            if len(value) != 1:
                raise ValueError('outcome read did not select exactly physical pipe1')
            value = value[0]
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid outcome register value: ' + name)
        return value

    def value(self, index):
        # Preserve the original 32-bit register's modular count semantics.
        return sum(self.read(bank, index) for bank in BANKS) & 0xffffffff

    def snapshot(self):
        return {bank: [self.read(bank, index) for index in range(25)] for bank in BANKS}


def incremented(snapshot, bank, index, count=1):
    result = {name: list(values) for name, values in snapshot.items()}
    result[bank][index] = (result[bank][index] + count) & 0xffffffff
    return result
