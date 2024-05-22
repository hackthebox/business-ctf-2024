import random
from enum import Enum


class Role(Enum):
    STEALTH = 'STEALTH SPECIALIST'
    ENGINEER = 'ENGINEER'
    DEMOLITIONS = 'DEMOLITIONS'
    SCAVENGER = 'SCAVENGER'
    HACKER = 'HACKER'


class Question:
    OPTIONS = 'ABCD'

    def __init__(self, question: str, answers: {str: Role}):
        self.question = question
        assert len(answers) == 4
        self.answers = answers

    def ask_question(self, idx: int, role_counts: {Role: int}):
        print(f'Question {idx}: {self.question}')

        choices = dict()

        for choice, answer in zip(Question.OPTIONS, self.answers.keys()):
            print(f'{choice}: {answer}')
            choices[choice] = answer

        choice = input('Choice: ').upper()

        if choice not in Question.OPTIONS:
            print('Invalid choice!')
            exit(0)

        role_counts[self.answers[choices[choice]]] += 1


role_counts = {r: 0 for r in Role}

questions = [
    Question(
        'Walking down the road, you see a scrap of metal poking out from the ground. What do you do?',
        {
            'Salvage it, having spare to fix machines never goes amiss': Role.ENGINEER,
            'Hide it better in case it ever comes in use': Role.STEALTH,
            'Use it to bribe the local gang for personal gain': Role.SCAVENGER,
            'Extract it and test its properties; perhaps it is something new': Role.DEMOLITIONS
        }
    ),

    Question(
        'You discover that an acquaintance of yours is a gang member responsible for the murder of many people. What do you do?',
        {
            'Kill him': Role.ENGINEER,
            'Ask to join the gang': Role.SCAVENGER,
            'Ignore the fact': Role.STEALTH,
            'Assert that you are joining the gang': Role.DEMOLITIONS
        }
    ),

    Question(
        'Your neighbour asks you to kill an individual. What course of action do you take?',
        {
            'Listen to your neighbour': Role.DEMOLITIONS,
            'Refuse': Role.STEALTH,
            'Tell your close friends and come up with a course of action': Role.HACKER,
            'Report it to the individual': Role.ENGINEER
        }
    ),

    Question(
        'A friend is injured and has a deep cut. How do you react?',
        {
            'Clean the wound and stem the bleeding': Role.SCAVENGER,
            'Slap a bandage on it and call it a day': Role.ENGINEER,
            'Offer to help': Role.DEMOLITIONS,
            'Ignore it, if they wanted help they would ask for it': Role.HACKER
        }
    ),

    Question(
        'There is a coup in the local city, and the pseudo-government is overthrown by a gang. How do you ensure your safety?',
        {
            'Stay low and keep your nose out of other people\'s business': Role.STEALTH,
            'Join the gang': Role.SCAVENGER,
            'Attempt to start communication with the gang and foster good relations': Role.HACKER,
            'Nothing, it doesn\'t affect you': Role.ENGINEER
        }
    ),
    Question(
        'Your team is required to relocate. What is the most important thing to ensure?',
        {
            'Everyone\'s opinion is considered': Role.DEMOLITIONS,
            'Quick and decisive action': Role.STEALTH,
            'Prioritizing the safety of the group': Role.HACKER,
            'Ensuring there are enough resources at the new location': Role.ENGINEER
        }
    ),

    Question(
        'If your group encounters a locked gate with no key available, what is your best course of action?',
        {
            'Look for another way around': Role.STEALTH,
            'Try to pick the lock': Role.SCAVENGER,
            'Break the gate down': Role.DEMOLITIONS,
            'Wait for someone to open it': Role.HACKER
        }
    ),

    Question(
        'When planning a raid on a gang’s supplies, what is crucial to consider?',
        {
            'The number of guards': Role.HACKER,
            'The time of day': Role.ENGINEER,
            'Escape routes': Role.SCAVENGER,
            'All of the above': Role.STEALTH
        }
    ),

    Question(
        'You find a stash of resources belonging to a local gang. What do you do?',
        {
            'Take everything you need': Role.SCAVENGER,
            'Take only what is essential for survival': Role.STEALTH,
            'Use it as leverage with the other gang': Role.DEMOLITIONS,
            'Analyse and see if there\'s anything immediately useful': Role.ENGINEER
        }
    ),

    Question(
        'You meet another group of survivors who are hostile. What is the most effective way to handle the situation?',
        {
            'Show aggression to establish dominance': Role.DEMOLITIONS,
            'Negotiate for peace and resources exchange': Role.HACKER,
            'Avoid them and leave quietly': Role.STEALTH,
            'Offer to join forces with them': Role.SCAVENGER
        }
    ),
]

for i, q in enumerate(questions):
    q.ask_question(i+1, role_counts)

# calculate most common role, randomising if multiple exist
max_roles = []
max_cnt = 0

for role, cnt in role_counts.items():
    if cnt > max_cnt:
        max_roles = [role]
        max_cnt = cnt
    elif cnt == max_cnt:
        max_roles.append(role)

final_role = random.choice(max_roles)

print(f'Congratulations, your final role is: {final_role.value.title()}')
print('I am sure you will be happy with it. If not, that\'s too bad - you should have done better.')

# print flag
with open('flag.txt', 'r') as f:
    flag = f.read()

print(f'Whoops, I nearly forgot - here\'s some useful information as well: {flag}')
