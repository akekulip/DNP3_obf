"""Launch a guarded Python helper through the lab's permitted sudo Python entry point."""
import shlex


def authorized_python(script, arguments):
    argv = [str(script)] + [str(value) for value in arguments]
    code = ('import os,runpy,sys; os.environ["DEFENSE4_HW_AUTHORIZED"]="1"; '
            'sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name="__main__")')
    return 'sudo -n python3 -c ' + shlex.quote(code) + ' ' + ' '.join(shlex.quote(value) for value in argv)
