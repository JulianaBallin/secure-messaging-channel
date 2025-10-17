"""
Decorador para garantir o rollback automático de transações de banco de dados em caso de erro.

Este decorador envolve uma função de operação de banco de dados, garantindo que se
qualquer exceção for levantada durante a execução da função, o método `rollback()`
do objeto de conexão/sessão do banco de dados (o primeiro argumento, 'db')
será chamado para desfazer quaisquer alterações pendentes.
"""

def safe_db_operation(func):
    """Decorator para garantir rollback automático em caso de erro."""
    def wrapper(db, *args, **kwargs):
        try:
            return func(db, *args, **kwargs)
        except Exception as e:
            print(f"⚠️ Erro: {e}")
            db.rollback()
            raise
    return wrapper
