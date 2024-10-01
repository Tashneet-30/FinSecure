from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist
from .forms import *
from .models import *
from .utils.encryption import generate_key, encrypt_value, decrypt_value
import os
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json


def encrypt_data(data, key):
    data = json.dumps(data).encode()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(data, AES.block_size))).decode('utf-8')

def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return json.loads(decrypted_data)


def logout_view(request):
    logout(request)
    return redirect('landing')

def landing(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = LoginForm(data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = authenticate(
                username=form.cleaned_data['username'], 
                password=form.cleaned_data['password'],
            )
            encryption_key=form.cleaned_data['encryption_key']
            if user is not None:
                login(request, user)
                request.session['encryption_key'] = form.cleaned_data['encryption_key']
                print("User logged in")
                print("Encryption key:", encryption_key)
                print("Session key:", request.session['encryption_key'])
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password')
        else:
            messages.error(request, 'Invalid username or password')

    return render(request, 'landing.html', {'form': form})

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            print("User registered")
            messages.success(request, 'Registration successful. Please log in.')
            return redirect('submit_financial_data')
        else:
            messages.error(request, 'Invalid registration details')
    
    else:
        form = RegisterForm()

    return render(request, 'register.html', {'form': form})

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.forms import ValidationError

@login_required
def submit_financial_data(request):
    if 'encryption_key' not in request.session:
        key = Fernet.generate_key()
        request.session['encryption_key'] = key.decode('utf-8')
    else:
        key = request.session['encryption_key'].encode('utf-8')

    fernet = Fernet(key)

    print("\n Encryption key:", key)
    

    try:
        personal_instance = Personal.objects.get(user=request.user)
        income_instance = Income.objects.get(user=request.user)
        expenses_instance = Expenses.objects.get(user=request.user)
        savings_instance = Savings.objects.get(user=request.user)
        assets_instance = Assets.objects.get(user=request.user)
        financial_goals_instance = FinancialGoals.objects.get(user=request.user)
        risk_profile_instance = RiskProfile.objects.get(user=request.user)

    except ObjectDoesNotExist:
        personal_instance = Personal(user=request.user)
        income_instance = Income(user=request.user)
        expenses_instance = Expenses(user=request.user)
        savings_instance = Savings(user=request.user)
        assets_instance = Assets(user=request.user)
        financial_goals_instance = FinancialGoals(user=request.user)
        risk_profile_instance = RiskProfile(user=request.user)

    if request.method == 'POST':
        post_data = request.POST.copy()
        post_data.setdefault('retirement_lifestyle', 'moderate')  # Default value for invalid choices

        post_data.setdefault('one_time_expenses', '0')
        post_data.setdefault('debt', '0')
        post_data.setdefault('retirement_savings', '0')
        post_data.setdefault('investments', '0')
        post_data.setdefault('return_on_investments', '0')
        post_data.setdefault('real_estates', '0')
        post_data.setdefault('vehicles', '0')
        post_data.setdefault('liabilities', '0')
        post_data.setdefault('other_assets', '0')
        post_data.setdefault('risk_tolerance', 'Medium')

        personal_form = PersonalForm(post_data, instance=personal_instance)
        income_form = IncomeForm(post_data, instance=income_instance)
        expenses_form = ExpensesForm(post_data, instance=expenses_instance)
        savings_form = SavingsForm(post_data, instance=savings_instance)
        assets_form = AssetsForm(post_data, instance=assets_instance)
        financial_goals_form = FinancialGoalsForm(post_data, instance=financial_goals_instance)
        risk_profile_form = RiskProfileForm(post_data, instance=risk_profile_instance)

        if (personal_form.is_valid() and income_form.is_valid() and expenses_form.is_valid() and
                savings_form.is_valid() and assets_form.is_valid() and financial_goals_form.is_valid() and
                risk_profile_form.is_valid()):
            
            # Encrypt and save Personal data
            for field in personal_form.cleaned_data:
                if field != 'user':
                    print("\n Field:", field)
                    print("\n Value:", personal_form.cleaned_data[field])
                    value = str(personal_form.cleaned_data[field]).encode('utf-8')
                    encrypted_value = fernet.encrypt(value)
                    setattr(personal_instance, field, encrypted_value.decode('utf-8'))
            personal_instance.save()

            # Encrypt and save Income data
            for field in income_form.cleaned_data:
                if field != 'user':
                    print("\n Field:", field)
                    print("\n Value:", income_form.cleaned_data[field])
                    value = str(income_form.cleaned_data[field]).encode('utf-8')
                    encrypted_value = fernet.encrypt(value)
                    setattr(income_instance, field, encrypted_value.decode('utf-8'))
            income_instance.save()

            # Encrypt and save Expenses data
            for field in expenses_form.cleaned_data:
                if field != 'user':
                    print("\n Field:", field)
                    print("\n Value:", expenses_form.cleaned_data[field])
                    value = str(expenses_form.cleaned_data[field]).encode('utf-8')
                    encrypted_value = fernet.encrypt(value)
                    setattr(expenses_instance, field, encrypted_value.decode('utf-8'))
            expenses_instance.save()

            # Encrypt and save Savings data
            for field in savings_form.cleaned_data:
                if field != 'user':
                    print("\n Field:", field)
                    print("\n Value:", savings_form.cleaned_data[field])
                    value = str(savings_form.cleaned_data[field]).encode('utf-8')
                    encrypted_value = fernet.encrypt(value)
                    setattr(savings_instance, field, encrypted_value.decode('utf-8'))
            savings_instance.save()

            # Encrypt and save Assets data
            for field in assets_form.cleaned_data:
                if field != 'user':
                    print("\n Field:", field)
                    print("\n Value:", assets_form.cleaned_data[field])
                    value = str(assets_form.cleaned_data[field]).encode('utf-8')
                    encrypted_value = fernet.encrypt(value)
                    setattr(assets_instance, field, encrypted_value.decode('utf-8'))
            assets_instance.save()

            # Save FinancialGoals and RiskProfile without encryption
            print("\n Financial Goals:", financial_goals_form.cleaned_data)
            print("\n Risk Profile:", risk_profile_form.cleaned_data)
            financial_goals_form.save()
            risk_profile_form.save()

            return redirect('display_key')
        
        else:
            print("\n Error:", personal_form.errors)
            print("\n Error:", income_form.errors)
            print("\n Error:", expenses_form.errors)
            print("\n Error:", savings_form.errors)
            print("\n Error:", assets_form.errors)
            print("\n Error:", financial_goals_form.errors)
            print("\n Error:", risk_profile_form.errors)
            

    else:
        personal_form = PersonalForm(instance=personal_instance)
        income_form = IncomeForm(instance=income_instance)
        expenses_form = ExpensesForm(instance=expenses_instance)
        savings_form = SavingsForm(instance=savings_instance)
        assets_form = AssetsForm(instance=assets_instance)
        financial_goals_form = FinancialGoalsForm(instance=financial_goals_instance)
        risk_profile_form = RiskProfileForm(instance=risk_profile_instance)

    context = {
        'personal_form': personal_form,
        'income_form': income_form,
        'expenses_form': expenses_form,
        'savings_form': savings_form,
        'assets_form': assets_form,
        'financial_goals_form': financial_goals_form,
        'risk_profile_form': risk_profile_form,
    }

    return render(request, 'data.html', context)

@login_required
def display_key(request):
    encryption_key = request.session.get('encryption_key', '')
    return render(request, 'display_key.html', {'encryption_key': encryption_key})


def dashboard(request):
    #decrypting name
    key = request.session['encryption_key']
    personal_instance = Personal.objects.get(user=request.user)
    name = personal_instance.name
    f = Fernet(key.encode())
    decrypted_name = f.decrypt(name.encode()).decode()
    print("\n Decrypted name:", decrypted_name)
    context = {
        'name': decrypted_name
    }
    return render(request, 'dashboard.html', context)

import math

def fire_number(request):
    # retrieving encryption key from session
    key = request.session['encryption_key']
    
    # fetching instances from the database
    personal_instance = Personal.objects.get(user=request.user)
    income_instance = Income.objects.get(user=request.user)
    expenses_instance = Expenses.objects.get(user=request.user)
    savings_instance = Savings.objects.get(user=request.user)
    assets_instance = Assets.objects.get(user=request.user)
    financial_goals_instance = FinancialGoals.objects.get(user=request.user)
    risk_profile_instance = RiskProfile.objects.get(user=request.user)

    f = Fernet(key.encode())

    # decrypting data
    monthly_income = int(f.decrypt(income_instance.monthly_income.encode()).decode())
    employer_contributions = int(f.decrypt(income_instance.employer_contributions.encode()).decode())
    monthly_expenses = int(f.decrypt(expenses_instance.monthly_expenses.encode()).decode())
    annual_expenses = int(f.decrypt(expenses_instance.annual_expenses.encode()).decode())
    one_time_expenses = int(f.decrypt(expenses_instance.one_time_expenses.encode()).decode())
    current_savings = int(f.decrypt(savings_instance.current_savings.encode()).decode())
    return_on_investments = float(f.decrypt(savings_instance.return_on_investments.encode()).decode()) / 100
    liabilities = int(f.decrypt(assets_instance.liabilities.encode()).decode())
    other_assets = int(f.decrypt(assets_instance.other_assets.encode()).decode())

    # incorporating financial goals (retirement lifestyle)
    if financial_goals_instance.retirement_lifestyle == 'luxurious':
        fire_multiple = 30
    elif financial_goals_instance.retirement_lifestyle == 'frugal':
        fire_multiple = 20
    else:  # moderate, comfortable
        fire_multiple = 25

    # FIRE number calculation adjusted for lifestyle
    fire_number = (monthly_expenses * 12) * fire_multiple

    # accounting for inflation (6% annual)
    inflation_rate = 0.06

    # factoring in employer contributions to savings
    monthly_income += employer_contributions

    # years to fire calculation with projected income growth
    expected_salary_growth = float(f.decrypt(income_instance.expected_salary_growth.encode()).decode()) / 100
    years_to_fire = (fire_number - current_savings) / (monthly_income * 12)

    # adjust for inflation over the years to FIRE
    fire_number_adjusted = fire_number * math.pow((1 + inflation_rate), years_to_fire)

    # including one-time expenses and liabilities
    net_assets = other_assets - liabilities - one_time_expenses

    # projected savings growth considering return on investments
    projected_savings_growth = current_savings * math.pow((1 + return_on_investments), years_to_fire)

    # final years to FIRE calculation, including salary growth and savings
    if expected_salary_growth > 0:
        # salary grows, so we estimate the future income and adjust the calculation
        future_income = monthly_income * math.pow((1 + expected_salary_growth), years_to_fire)
        years_to_fire = (fire_number_adjusted - projected_savings_growth) / (future_income * 12)
    else:
        # no salary growth
        years_to_fire = (fire_number_adjusted - projected_savings_growth) / (monthly_income * 12)

    # savings rate calculation
    savings_rate = (current_savings / (monthly_income * 12)) * 100

    context = {
        'fire_number': int(fire_number_adjusted),
        'years_to_fire': int(years_to_fire),
        'savings_rate': int(savings_rate),
        'net_assets': net_assets,
        'projected_savings_growth': int(projected_savings_growth),
    }

    return render(request, 'fire_number.html', context)

# @login_required
# def submit_financial_data(request):
#     if 'encryption_key' not in request.session:
#         return redirect('set_encryption_key')

#     key = request.session['encryption_key']

#     if request.method == 'POST':
#         forms = {
#             'personal_form': PersonalForm(request.POST),
#             'income_form': IncomeForm(request.POST),
#             'expenses_form': ExpensesForm(request.POST),
#             'savings_form': SavingsForm(request.POST),
#             'assets_form': AssetsForm(request.POST),
#         }

#         if all(form.is_valid() for form in forms.values()):
#             for form in forms.values():
#                 instance = form.save(commit=False)
#                 for field in instance._meta.fields:
#                     if isinstance(field, EncryptedField):
#                         value = getattr(instance, field.name)
#                         encrypted_value = encrypt_value(value, key)
#                         setattr(instance, field.name, encrypted_value)
#                 instance.save()
#             return redirect('financial_summary')

#     else:
#         forms = {
#             'personal_form': PersonalForm(),
#             'income_form': IncomeForm(),
#             'expenses_form': ExpensesForm(),
#             'savings_form': SavingsForm(),
#             'assets_form': AssetsForm(),
#         }

#     return render(request, 'data.html', forms)


# @login_required
# def set_encryption_key(request):
#     if request.method == 'POST':
#         password = request.POST.get('password')
#         salt = os.urandom(16)
#         key = generate_key(password, salt)
#         request.session['encryption_key'] = key.decode()
#         request.session['salt'] = salt
#         return redirect('submit_financial_data')
#     return render(request, 'set_encryption_key.html')

# @login_required
# def financial_summary(request):
#     if 'encryption_key' not in request.session:
#         return redirect('set_encryption_key')

#     key = request.session['encryption_key']

#     # Fetch and decrypt data
#     personal = Personal.objects.get(user=request.user)
#     income = Income.objects.get(user=request.user)
#     # ... fetch other models

#     for field in personal._meta.fields:
#         if isinstance(field, EncryptedField):
#             value = getattr(personal, field.name)
#             decrypted_value = decrypt_value(value, key)
#             setattr(personal, field.name, decrypted_value)

#     # Decrypt other models similarly

#     context = {
#         'personal': personal,
#         'income': income,
#         # ... other decrypted data
#     }
#     return render(request, 'financial_summary.html', context)